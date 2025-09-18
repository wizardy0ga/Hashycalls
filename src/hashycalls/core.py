import os
import re
import sys
import json
from hashycalls.colors import *

# -------------------------- Constants --------------------------
VERSION = "2.1.1"

NAME_LOOKUP  = os.path.join( os.path.dirname( os.path.abspath( __file__ ) ), 'rsrc', 'data', 'name-conversion.json' )
TYPE_LOOKUP  = os.path.join( os.path.dirname( os.path.abspath( __file__ ) ), 'rsrc', 'data', 'type-conversion.json' )
WIN32_DATA   = os.path.join( os.path.dirname( os.path.abspath( __file__ ) ), 'rsrc', 'data', 'winapi.json' )
DJB2_FILE    = os.path.join( os.path.dirname( os.path.abspath( __file__ ) ), 'rsrc', 'code', 'templates', 'djb2.c' )
MURMUR_FILE  = os.path.join( os.path.dirname( os.path.abspath( __file__ ) ), 'rsrc', 'code', 'templates', 'murmur.c' )
HEADER_FILE  = os.path.join( os.path.dirname( os.path.abspath( __file__ ) ), 'rsrc', 'code', 'solution file', 'src', 'hashycalls.h' )
SOURCE_FILE  = os.path.join( os.path.dirname( os.path.abspath( __file__ ) ), 'rsrc', 'code', 'solution file', 'src', 'hashycalls.c' )

# ---------------------- Import Data Sets ---------------------
with open( WIN32_DATA, 'r' ) as file:
    win32_data = json.loads( file.read() )
with open( TYPE_LOOKUP, 'r' ) as file:
    illegal_type_lookup = json.loads( file.read() )
with open( NAME_LOOKUP, 'r' ) as file:
    name_change_lookup = json.loads( file.read() )

# --------------------------- Classes -------------------------
class ApiCall( object ):
    """
    Represents an api call to be resolved by hash & used in the sourced code such as LoadLibraryA, NtAllocateVirtualMemory, etc.

    Attributes:
        data: dictionary    -> contains all of the information available about the function call from json dataset (rsrc/data/winapi.json).
        hash: string        -> A hash of the function name.
        module_hash: string -> A hash of the required module.
        name: string        -> The name of the function call.
        module: string      -> The name of the module required by the function.
        prototype: string   -> The prototype string definition of the function
    """
    def __init__( self, name: str ):
        if name not in win32_data.keys():
            raise Exception( f"{ RED }{ name }{ END } is not a valid function listed in { YELLOW }{ WIN32_DATA }{ END }. Add this function to dataset if this is a mistake." )
        self.data           = win32_data[ name ]
        self.hash           = ""
        self.module_hash    = ""
        self.name           = name
        self.module         = self.data['dll'].lower()
        
        # Cleanup unnecessary naming conventions from microsoft before creating prototype. Requires 
        # user to modify output source code if left untouched. Example, HINTERNET is actually LPVOID 
        # but HINTERNET is not included in default win32 header so compilation fails due to missing type definition.
        if self.data['return_type'] in illegal_type_lookup:
            self.data['return_type'] = illegal_type_lookup[ self.data['return_type'] ]
        for param in self.data['arguments']:
            if param[ 'type' ] in illegal_type_lookup:
                param[ 'type' ] = illegal_type_lookup[ param[ 'type' ] ]
        self.prototype = self.create_prototype()

    def create_prototype( self ):
        """ 
        Create the prototype string for the apicall to be placed in the HWINAPI structure
        LPVOID ( WINAPI* VirtualAlloc ) ( LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect );
        """
        prototype = f"{ self.data['return_type'] } ( WINAPI* { self.name } ) ( "
        if self.data['n_arguments'] > 0:
            for param, index in zip( self.data['arguments'], range( 0, self.data['n_arguments'] ) ):
                prototype += f"{ param['type'] } { param['name'] }, "
                if index == self.data['n_arguments'] - 1:
                    prototype = f"{ prototype[ :-2 ] } )"
        else:
            prototype = f'{ prototype[:-1] })'
        return prototype


class Win32Api( object ):
    """ 
    Represents the win32 api call structure. This structure is a core component, defining required
    module handles & function prototypes as members. Execution of all functions is done through
    this structure.

    typedef struct 
    {
        struct
        {
            HMODULE Kernel32;
            HMODULE User32;
        }
        Modules;

        struct
        {
            DWORD ( WINAPI* GetCurrentProcessId ) ();
        }
        Kernel32;

        struct
        {
            int ( WINAPI* MessageBoxA ) ( HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType );
        }
        User32;
    }
    HWINAPI, *PHWINAPI;
    
    Attributes:
        apicalls: list                  -> A list of ApiCall objects
        using_external_modules: bool    -> True if structure requires modules other than kernel32, ntdll & kernelbase.
        modules: dictionary             -> The dlls required by the structure. Dictionary syntax-> { dll_name: { name: name, module_hash: module_hash, member_name: member_name } }
        structure: string               -> String of the structure after initialization            
    """
    def __init__( self, apicalls: list ):
        self.apicalls                   = apicalls
        self.using_external_modules     = False
        self.modules                    = {}
        self.structure                  = self.create_structure()
        # Determine if external modules are required
        for module in self.modules:
            if module not in ['kernel32.dll', 'ntdll.dll', 'kernelbase.dll']:
                self.using_external_modules = True
        
    def create_structure( self ):
        """ Create the HWINAPI structure """
        structure = "typedef struct \n{\n\tstruct\n\t{\n"

        # Collect the module information & add 'Modules' struct
        for function in self.apicalls:
            # Validate dll file names
            match function.module:
                case '':
                    raise Exception( f"{ RED }{ function.name }{ END } has no module specified in 'dll' key. Add the dll file to this key." )
                case _ if not function.module.endswith('.dll'):
                    raise Exception( f"The module in { RED }{ function.name }{ END } is invalid, it should end with .dll. Got module -> { function.module }")
            # Collect information
            if function.module not in self.modules.keys():
                self.modules[ function.module ] = { 
                        'name': function.module, 
                        'hash': function.module_hash,
                        'member_name': function.module.replace('.dll', '').replace( function.module[0], function.module[0].upper() ) 
                    }
                structure   += f"\t\tHMODULE { self.modules[ function.module ][ 'member_name' ] };\n"
        structure += "\t}\n\tModules;\n"
        
        # Make sure function calls are in correct order. Just need to be grouped by dll.
        # This ensures the FUNCTION_HASHES list order matches the order of the structure
        # definitions, providing accurate address resolution via parallelism
        new_list = []
        for module in self.modules:
            new_list += [ function for function in self.apicalls if function.module == module ]
        self.apicalls = new_list
        
        # Add function prototypes
        for module in self.modules.values():
            structure += "\n\tstruct\n\t{\n"
            for function in self.apicalls:
                if function.module == module['name']:
                    structure       += f"\t\t{ function.prototype };\n"
            structure += f"\t}}\n\t{ module[ 'member_name' ] };\n"
        structure += "}\nHWINAPI, *PHWINAPI;"
        return structure


class SourceCode( object ):
    """
    Represents the source code of a file. Intended to be used as a parent object for other source code objects.

    Attributes:
        filename: string        -> The name of the file to write when writing to disk
        path_on_disk: string    -> The path of the file after it was written to disk
        launguage: string       -> The scripting or programming language associated with the source code
        comment_regex: list     -> A list of regex expressions for possible comments to be removed from the source code
        source_file: string     -> A path to a file on disk to use as the source code. Contents are only read, not modified.
        header_content: string  -> A string containing the base comment banner to use at the top of the source code.
        content: string         -> The contents of the source code
    """
    def __init__ ( self, source_file: str, filename: str ):
        self.filename       = filename
        self.path_on_disk   = ""
        self.language       = ""
        self.comment_regex  = []
        self.source_file    = source_file
        self.header_content = \
            f"Generated with hashycalls v-{ VERSION }\nCommandline: { ' '.join( sys.argv ) }" 
        
        with open( self.source_file, 'r' ) as file:
            self.content = file.read()
    
    def replace_content( self, new_content: str, pattern: str, count = 1 ) -> None:
        """ Replace the content of a file via regex matching """
        self.content    = re.sub( pattern = pattern, repl = new_content, string = self.content, count = count )

    def write_to_dir( self, directory: str ) -> None:
        """ Write the source file to a directory """
        if not os.path.isdir( directory ):
            raise Exception( f"{ directory } is not a valid directory on the file system" )
        self.path_on_disk = os.path.join( directory, self.filename )
        with open( self.path_on_disk, 'w' ) as file:
            file.write( self.content )
        self.path_on_disk = self.path_on_disk
            
    def remove_comments( self ) -> None:
        """ Remove comments from the source code. """
        for pattern in self.comment_regex:
            self.replace_content( new_content = '', pattern = pattern, count = 0 )
    
    def remove_blank_lines( self ) -> str:
        """ Remove all blank lines greater than 2 from source """
        self.replace_content( new_content = '\n', pattern = r'(?m)(?:^[ \t]*\r?\n){2,}', count = 0 )

    def insert_header( self, additional_content = "" ) -> str:
        """ Insert a comment block at the top of the file, describing the file """
        match self.language:
            case 'asm':
                header = ";\n"
                for line in self.header_content.splitlines():
                    header += f"; { line }\n"
                for line in additional_content.splitlines():
                    header += f"; { line }\n"
                header += ";\n"
            case 'c':
                header = "/*\n"
                for line in self.header_content.splitlines():
                    header += f" * { line }\n"
                for line in additional_content.splitlines():
                    header += f" * { line }\n"
                header += "*/\n"

        header += self.content
        self.content = header


class HashycallsFile( SourceCode ):
    """ 
    Base object for .c & .h hashycalls files.
    
    Unique Attributes:
        seed: int                   -> The seed to be used for the hashing function
        algo: str                   -> A string representing the hashing function to use in the source code
        api_call_list: Win32Api     -> A Win32Api object representing the HWINAPI structure
        hash_function: function     -> The hashing function to be used
        hash_function_file: string  -> The path of the hashing function source code template
        hash_function_name: string  -> The name of the hasing functions defined in hash_function_file
    """
    def __init__( self, apicalls: list, source_file: str, filename: str, algo: str, seed: int ):
        super().__init__( source_file, filename )
        self.seed           = seed
        self.algo           = algo
        self.language       = "c"
        self.comment_regex  = [
            r'//.*'                             # Single line starting with //
            , r'\/\*.*?\*\/'                    # Single line comments between /* */
            , r'(?s)/\*(?:(?!@brief).)*?\*/'    # Multi line comments between /* */ without @brief comment (Keep function info)
        ]
        # Set hashing algorithm
        match algo:
            case 'sdbm':
                self.hash_function      = self.hash_sdbm
            case 'djb2':
                self.hash_function      = self.hash_djb2
                self.hash_function_file = DJB2_FILE
                self.hash_function_name = 'HashStringDjb2'
            case 'murmur':
                self.hash_function      = self.hash_murmur
                self.hash_function_file = MURMUR_FILE
                self.hash_function_name = 'HashStringMurmur'
            case _:
                raise Exception( f"{ RED } { algo } { END } is not a valid hashing algorithm implemented in hashycalls." )
            
        # Create api call objects & set function / dll hashes
        self.api_call_list = [ ApiCall( apicall ) for apicall in apicalls ]
        for function in self.api_call_list:
            # Some functions have different names in the header file than what's in the dll. An example is 
            # EnumProcesses since it's a actually a macro for K32EnumProcesses. This function lives in 
            # Kernel32.dll as K32EnumProcesses. This loc accounts for this & hashes the proper name found 
            # in /rsrc/data/name-conversion.json
            target = function.name if function not in name_change_lookup else name_change_lookup[ function ]
            function.hash           = self.hash_function( target )
            function.module_hash    = self.hash_function( function.module )
        self.api_call_list = Win32Api( apicalls = self.api_call_list)

    def hash_djb2( self, string: str ):
        """ Hash a string using DJB2 algorithm """
        hash = self.seed
        for i in string:
            hash = ( ( hash << 5 ) + hash ) + ord( i )
        return hex( hash & 0xFFFFFFFF ).upper().replace( 'X', 'x' )

    def hash_sdbm( self, string: str ) -> str:
        """ Hash a string using the SDBM hash algorithm -> 0xDEADBEEF """
        Hash = self.seed
        for x in list( string ):
            Hash = ord( x ) + ( Hash << 6 ) + ( Hash << 16 ) - Hash
        return "0x%X" % ( Hash & 0xFFFFFFFF )

    def hash_murmur( self, string: str ) -> str:
        """ Hash a string with MurmurHash3 algo """
        string = string.encode()
        length = len(string)
        Hash = self.seed
        if length > 3:
            idx = length >> 2
            for i in range(idx):
                start = i * 4
                cnt = int.from_bytes(string[start:start+4], byteorder='little')
                cnt = (cnt * 0xcc9e2d51) & 0xffffffff
                cnt = ((cnt << 15) | (cnt >> 17)) & 0xffffffff
                cnt = (cnt * 0x1b873593) & 0xffffffff
                Hash ^= cnt
                Hash = ((Hash << 13) | (Hash >> 19)) & 0xffffffff
                Hash = ((Hash * 5) + 0xe6546b64) & 0xffffffff
        remaining = length & 3
        if remaining:
            cnt = 0
            start_pos = (length >> 2) * 4 + remaining - 1
            for i in range(remaining):
                cnt = (cnt << 8) & 0xffffffff
                cnt |= string[start_pos - i]
            cnt = (cnt * 0xcc9e2d51) & 0xffffffff
            cnt = ((cnt << 15) | (cnt >> 17)) & 0xffffffff
            cnt = (cnt * 0x1b873593) & 0xffffffff
            Hash ^= cnt
        Hash ^= length
        Hash ^= Hash >> 16
        Hash = (Hash * 0x85ebca6b) & 0xffffffff
        Hash ^= Hash >> 13
        Hash = (Hash * 0xc2b2ae35) & 0xffffffff
        Hash ^= Hash >> 16
        return "0x%X" % Hash

class HashycallsHeader( HashycallsFile ):
    """ Represents the hashycalls header file """
    def __init__( self, apicalls: list, globals: bool, api_list_name: str, algo: str, seed: int ):
        super().__init__( source_file = HEADER_FILE, filename = 'hashycalls.h', apicalls = apicalls, algo = algo, seed = seed )
        
        # Set control macros
        if not globals:
            self.replace_content( '// # define hc_GLOBAL', r'# define hc_GLOBAL' )
        if api_list_name != 'hWin32':
            self.replace_content( api_list_name, r'hWin32' )
        
        # Add api call list structure
        self.replace_content( self.api_call_list.structure, r'(?s)typedef struct \n{\n\tstruct.*}\nHWINAPI, \*PHWINAPI;' )
        
        # Add dll name hashes
        modules = ""
        for module in self.api_call_list.modules.values():
            modules += f"# define hc_{ module[ 'member_name' ] }\t{ module[ 'hash' ] }\n"
        self.replace_content( modules, r'(?s)# define hc_Kernel32\t0x[0-9A-F]*.*# define hc_User32\t\t0x[0-9A-F]*' )
        
        # Add function hashes 
        function_hashes = ""
        for function in self.api_call_list.apicalls:
            function_hashes += f"# define hc_{ function.name } { function.hash }\n"
        self.replace_content( function_hashes, r'(?s)# define hc_GetCurrentProcessId*.*# define hc_MessageBoxA\t\t\t\t0x[0-9A-F]*\n' )


class HashycallsSource( HashycallsFile ):
    """ Represents the hashycalls source (.c) file """
    def __init__( self, apicalls: list, globals: bool, algo: str, seed: int, debug: bool ):
        super().__init__( source_file = SOURCE_FILE, apicalls = apicalls, filename = 'hashycalls.c', algo = algo, seed = seed )
        
        # Set control macros
        if not debug:
            self.replace_content('// # define DEBUG', r'# define DEBUG')
        self.replace_content( '', r'# define USING_EXTERNAL_MODULES\n' )
        
        # Modify source based on presence of external modules
        match self.api_call_list.using_external_modules:
            case False:
                self.replace_content( '', r'(?s)# ifdef USING_EXTERNAL_MODULES\ntypedef HANDLE.*lpFindFileData\s\);\n# endif \/\/ USING_EXTERNAL_MODULES\n')  # Remove function prototypes required for LoadDllFromSystem32ByHash
                self.replace_content( '', \
                    r'(?s)# ifdef USING_EXTERNAL_MODULES.*static HMODULE LoadDllFromSystem32ByHash.*return NULL;\n\}\n# endif \/\/ USING_EXTERNAL_MODULES' )  # Remove LoadDllFromSystem32ByHash function
                self.replace_content( '', \
                    r'(?s)# ifdef USING_EXTERNAL_MODULES\n\t\t\tdbg.*\t\t\t\}\n# endif \/\/ USING_EXTERNAL_MODULES\n' )                                       # Remove LoadDllFromSystem32ByHash call from InitApiCalls() routine
                self.replace_content( '', '# define FindFirstFileA_Hash.*\n# define FindNextFileA_Hash.*\n' )
                self.replace_content( '', r'# ifndef USING_EXTERNAL_MODULES\n' )                                                                              # Remove preprocessor from InitApiCalls()
                self.replace_content( '', r'# endif \/\/ !USING_EXTERNAL_MODULES\n')                                                                          # Remove preprocessor from InitApiCalls()
            case True:
                self.replace_content( '', r'# ifdef USING_EXTERNAL_MODULES\n', count = 0 )                                                                    # Remove preprocessor from entire source
                self.replace_content( '', r'# endif \/\/ USING_EXTERNAL_MODULES\n', count = 0 )                                                               # Remove preprocessor from entire source
                self.replace_content( '', r'(?s)# ifndef USING_EXTERNAL_MODULES.*# endif \/\/ !USING_EXTERNAL_MODULES\n')                                     # Remove default routine from InitApiCalls()
        
        # Define the amount of modules required by the configuration
        self.replace_content( f'# define MODULES { len( self.api_call_list.modules ) }', r'# define MODULES.*')
        
        # Add hash seed, string / default function hashes
        self.replace_content( f'# define HASH_SEED { seed }', r'# define HASH_SEED\t{4}[0-9]{4}')
        self.replace_content( f'# define WINDIR { self.hash_function( 'windir' ) }', r'# define WINDIR\t{5}0x[A-F0-9]{8}')
        self.replace_content( f'# define SYSTEM32 { self.hash_function( 'System32' ) }', r'# define SYSTEM32\t{4}0x[A-F0-9]{8}')
        self.replace_content( f'# define NTDLL { self.hash_function( 'ntdll.dll' ) }', r'# define NTDLL.*' )
        self.replace_content( f'# define KERNEL32 {self.hash_function( 'kernel32.dll' ) }', r'# define KERNEL32.*' )
        self.replace_content( f'# define LoadLibraryA_Hash { self.hash_function( 'LoadLibraryA' ) }', r'# define LoadLibraryA_Hash\t{4}0x[A-F0-9]{8}' )
        self.replace_content( f'# define NtAllocateVirtualMemory_Hash { self.hash_function( 'NtAllocateVirtualMemory' ) }', r'# define NtAllocateVirtualMemory_Hash.*')
        if self.api_call_list.using_external_modules:
            self.replace_content( f'# define FindFirstFileA_Hash { self.hash_function( 'FindFirstFileA' ) }', r'# define FindFirstFileA_Hash\t{3}0x[A-F0-9]{8}' )
            self.replace_content( f'# define FindNextFileA_Hash { self.hash_function( 'FindNextFileA' ) }', r'# define FindNextFileA_Hash\t{4}0x[A-F0-9]{8}' )
        
        # Define module & function hash lists
        module_hash_list    = "# define MODULE_HASHES \\\n"
        function_hash_list  = "# define FUNCTION_HASHES \\\n"
        for module in self.api_call_list.modules.values():
            module_hash_list += f'\thc_{ module['member_name'] }, \\\n'
        for function in self.api_call_list.apicalls:
            function_hash_list += f"\t hc_{ function.name }, \\\n"
        module_hash_list    = f'{ module_hash_list[:-4] } \\\\'
        function_hash_list  = f'{ function_hash_list[:-4] } \\\\'
        self.replace_content( module_hash_list, r'(?s)# define MODULE_HASHES\t\\.*\thc_User32 \\' )
        self.replace_content( function_hash_list, r'(?s)# define FUNCTION_HASHES \\.*hc_MessageBoxA \\' )
        
        # Build function population routine
        population_routine = ""
        for module in self.api_call_list.modules.values():
            population_routine += f"\tPOPULATE_FUNCTIONS( { module[ 'member_name' ]} )\n"
        self.replace_content( population_routine, r'(?s)\tPOPULATE.*_FUNCTIONS\( User32 \);\n' )
        self.replace_content( f'pFunction = ( PVOID* ) &( hc_API_VAR_NAME->{ next(iter(self.api_call_list.modules.values()))['member_name'] } );', r'pFunction = \( PVOID\* \) &\( hc_API_VAR_NAME->Kernel32 \);' )
        
        # Set hashing functions
        if self.algo != 'sdbm':
            with open( self.hash_function_file, 'r' ) as file:
                self.replace_content( file.read(), r'(?s)static DWORD HashStringSdbmA.*static DWORD HashStringSdbmW.*\treturn Hash;\n\}' )
            self.replace_content( f'# define HashStringA( String ) { self.hash_function_name }A( String )', r'# define HashStringA\( String \).*' )
            self.replace_content( f'# define HashStringW( String ) { self.hash_function_name }W( String )', r'# define HashStringW\( String \).*' )

# --------------------------- Classes -------------------------
class HashyCalls( object ):
    """ Container object for hashycalls header & source files """
    def __init__( self, apicalls: list, globals: bool, api_list_name: str, algo: str, seed: int, debug: bool ):
        self.header = HashycallsHeader( apicalls, globals, api_list_name, algo, seed )
        self.source = HashycallsSource( apicalls, globals, algo, seed, debug )