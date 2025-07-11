/*
 * Generated with hashycalls v-2.0.0
 * Template version: 2.0.0
 * Commandline: C:\Users\Admin\AppData\Roaming\Python\Python313\Scripts\hashycalls --apicalls CreateToolhelp32Snapshot Process32FirstW Process32NextW wcscmp OpenProcess VirtualAllocEx VirtualProtectEx WriteProcessMemory CreateRemoteThread WaitForSingleObject CloseHandle --quiet --debug --globals --outdir .\example-output\
 * ID: d0f1a209-b12a-4531-81b5-f479b9e85544
 * Using function calls:
 * 	[+] - CreateToolhelp32Snapshot
 * 	[+] - Process32FirstW
 * 	[+] - Process32NextW
 * 	[+] - wcscmp
 * 	[+] - OpenProcess
 * 	[+] - VirtualAllocEx
 * 	[+] - VirtualProtectEx
 * 	[+] - WriteProcessMemory
 * 	[+] - CreateRemoteThread
 * 	[+] - WaitForSingleObject
 * 	[+] - CloseHandle
*/
# include "hashycalls.h"

/* ------------------------- Macros ------------------------- */
// --- Control
# define DEBUG

// --- Values
# define NT_SUCCESS 0x0
# define MODULES 2

// --- String Hashes
# define HASH_SEED 2558
# define WINDIR 0x5B24336F
# define SYSTEM32 0xC25AA7AC

// --- Default library hashes
# define NTDLL 0xD3171196
# define KERNEL32 0x4790B670

// --- Default function hashes
# define NtAllocateVirtualMemory_Hash 0x19EC850B
# define LoadLibraryA_Hash 0x973D8BEA

// --- Module & function hash lists
# define MODULE_HASHES \
	hc_Kernel32, \
	hc_Ntdll \

# define FUNCTION_HASHES \
	 hc_CreateToolhelp32Snapshot, \
	 hc_Process32FirstW, \
	 hc_Process32NextW, \
	 hc_OpenProcess, \
	 hc_VirtualAllocEx, \
	 hc_VirtualProtectEx, \
	 hc_WriteProcessMemory, \
	 hc_CreateRemoteThread, \
	 hc_WaitForSingleObject, \
	 hc_CloseHandle, \
	 hc_wcscmp \

// --- Functions
# ifdef DEBUG
# include <stdio.h>
# define dbg(msg, ...) printf("[DEBUG]::Hashycalls.%s.L%d -> " msg "\n", __func__, __LINE__, ##__VA_ARGS__)
# endif
# ifndef DEBUG
# define dbg(msg, ...) do {} while (0)
# endif

# define HashStringA( String ) HashStringSdbmA( String )
# define HashStringW( String ) HashStringSdbmW( String )

# define POPULATE_FUNCTIONS( Module ) \
	for ( unsigned int i = 0; i < sizeof( hc_API_VAR_NAME->Module ) / sizeof(PVOID); i++ ) \
	{						\
		if ( ( *pFunction = GetProcAddressByHash( hc_API_VAR_NAME->Modules.Module, FunctionHashes[ i + TotalFunctions ] ) ) == NULL ) \
			return FALSE;	\
							\
		pFunction++;		\
	}						\
	TotalFunctions += sizeof( hc_API_VAR_NAME->Module ) / sizeof( PVOID);\

/* ----------------------- Prototypes ----------------------- */
typedef NTSTATUS	( NTAPI*  fpNtAllocateVirtualMemory )	( HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect );
typedef HMODULE		( WINAPI* fpLoadLibraryA )				( LPCSTR lpLibFileName );

/* ----------------------- Structures ----------------------- */
typedef struct _UNICODE_STRING_
{
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
}
UNICODE_STRING_, * PUNICODE_STRING_;

typedef struct _LOADER_DATA_TABLE_ENTRY
{
    LIST_ENTRY      InLoadOrderLinks;
    LIST_ENTRY      InMemoryOrderLinks;
    LIST_ENTRY      InInitializationOrderLinks;
    PVOID           DllBase;
    PVOID           EntryPoint;
    ULONG           SizeOfImage;
    UNICODE_STRING_ FullDllName;
    UNICODE_STRING_ BaseDllName;
} 
LOADER_DATA_TABLE_ENTRY, * PLOADER_DATA_TABLE_ENTRY;

typedef struct _PEB_LOADER_DATA
{
    ULONG       Length;
    BOOLEAN     Initialized;
    HANDLE      SsHandle;
    LIST_ENTRY  InLoadOrderModuleList;
    LIST_ENTRY  InMemoryOrderModuleList;
    LIST_ENTRY  InInitializationOrderModuleList;
    PVOID       EntryInProgress;
    BOOLEAN     ShutdownInProgress;
    HANDLE      ShutdownThreadId;
} 
PEB_LOADER_DATA, * PPEB_LOADER_DATA;

typedef struct _CURDIR
{
    UNICODE_STRING_ DosPath;
    HANDLE          Handle;
}
CURDIR, * PCURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG           MaximumLength;
    ULONG           Length;
    ULONG           Flags;
    ULONG           DebugFlags;
    HANDLE          ConsoleHandle;
    ULONG           ConsoleFlags;
    HANDLE          StandardInput;
    HANDLE          StandardOutput;
    HANDLE          StandardError;
    CURDIR          CurrentDirectory;
    UNICODE_STRING_ DllPath;
    UNICODE_STRING_ ImagePathName;
    UNICODE_STRING_ CommandLine;
    PVOID           Environment;
} 
RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PROC_ENV_BLOCK
{
    BOOLEAN                         InheritedAddressSpace;
    BOOLEAN                         ReadImageFileExecOptions;
    BOOLEAN                         BeingDebugged;
    HANDLE                          Mutant;
    PVOID                           ImageBaseAddress;
    PPEB_LOADER_DATA                Ldr;
    PRTL_USER_PROCESS_PARAMETERS    ProcessParameters;
} 
PROC_ENV_BLOCK, * PPROC_ENV_BLOCK;

# ifdef hc_GLOBAL
/* ----------------------- Globals ----------------------- */
PHWINAPI hc_API_VAR_NAME;
# endif

/* ------------------- Internal Functions ------------------- */
static DWORD HashStringSdbmA( _In_ LPCSTR String )
{
	ULONG	Hash = HASH_SEED;
	INT		c;
	while ( c = *String++ )
		Hash = c + ( Hash << 6 ) + ( Hash << 16 ) - Hash;

	return Hash;
}

static DWORD HashStringSdbmW( _In_ LPCWSTR String )
{
	ULONG	Hash = HASH_SEED;
	INT		c;
	while ( c = *String++ )
		Hash = c + ( Hash << 6 ) + ( Hash << 16 ) - Hash;

	return Hash;
}

static SIZE_T StringLengthA( _In_ LPCSTR String )
{
    LPCSTR String2;
    for (String2 = String; *String2; ++String2);
    return (String2 - String);
}

static VOID WCharToChar( OUT PCHAR Dest, IN PWCHAR Source ) 
{
    while ( TRUE ) 
        if ( !( *Dest++ = ( CHAR )*Source++ ) ) 
            break;
}

static SIZE_T StringLengthW( _In_ LPCWSTR String )
{
    LPCWSTR String2;
    for ( String2 = String; *String2; ++String2 );
    return ( String2 - String );
}

static PCHAR StringCopyA( _Inout_ PCHAR String1, _In_ LPCSTR String2 )
{
    PCHAR p = String1;
    while ( ( *p++ = *String2++ ) != 0 );
    return String1;
}

static PCHAR StringConcatA( _Inout_ PCHAR String, _In_ LPCSTR String2 )
{
    StringCopyA( &String[ StringLengthA( String ) ], String2 );
    return String;
}

static VOID ToLower(IN PCHAR String)
{
    INT		Index	= 0;
    CHAR	Letter	= 0;
    for ( Index = 0; Index < StringLengthA( String ); Index++ ) 
	{
        Letter = String[ Index ];
        String[ Index ] = ( Letter >= 'A' && Letter <= 'Z' ) ? Letter + 0x20 : Letter;
    }
}

/*
	@brief
		Gets the value of an environment variable using a hash of
		the target variable name.

	@param[in]  DWORD Hash
		A hash of the environment variable to locate
	@param[out] PCHAR OutBuffer
		A buffer to write the variable value to
	@param[in]  DWORD BufferSize
		The size of the buffer

	@return SIZE_T
		Returns the size of the string if the value was found, else -1 
*/
static SIZE_T GetEnvironmentVarByHash( IN DWORD Hash, OUT PCHAR OutBuffer, IN SIZE_T BufferSize ) 
{
    PBYTE	pEnvironmentVariables, pTmp;
    SIZE_T	StringSize;
    CHAR	VarNameBuffer[ MAX_PATH ];
    INT		Index = 0;

	/* Get a pointer to the environment variables */
	if ( ( pEnvironmentVariables = ( ( PPROC_ENV_BLOCK )__readgsqword( 0x60 ) )->ProcessParameters->Environment ) == NULL )
		return -1;

    while ( TRUE ) 
	{
        if ( ( StringSize = StringLengthW( ( LPCWSTR )pEnvironmentVariables ) ) != 0 ) 
		{
            pTmp	= pEnvironmentVariables;
            Index	= 0;

			/* Get the name of the variable */
            while ( *pTmp != '=' && Index < MAX_PATH ) 
			{
                VarNameBuffer[ Index++ ] = *pTmp++;
            }
            VarNameBuffer[ Index ] = '\0';

			/* Check if hash of variable names matches & copy value to outbuffer if match */
            if ( HashStringW( ( LPCWSTR )VarNameBuffer ) == Hash ) 
			{
				if ( ( StringSize = StringLengthW( ( PWCHAR )( pEnvironmentVariables + Index + sizeof( WCHAR ) ) ) ) < BufferSize )
				{
					WCharToChar( ( PCHAR )OutBuffer, ( PWCHAR )( pEnvironmentVariables + Index + sizeof( WCHAR ) ) );
					dbg( "Resolved 0x%0.8X to (%S). Got value (%s).", Hash, ( PWCHAR )VarNameBuffer, OutBuffer );
					return StringLengthW( ( LPCWSTR )OutBuffer );
				}
				else 
				{
					dbg( "Buffer overflow prevented! String is %lld bytes, buffer is %lld bytes. Need %lld more bytes.", StringSize, BufferSize, StringSize - BufferSize );
					return -1;
				}
            }
        }
        else 
		{
            break;
        }
        pEnvironmentVariables += ( StringSize * sizeof( WCHAR ) ) + sizeof( WCHAR );
    }
    dbg( "Could not translate 0x%0.8X to any environment variables", Hash );
    return -1;
}

/* ------------------- External Functions ------------------- */
HMODULE GetModuleHandleByHash( IN DWORD Hash ) 
{

    CHAR						ModuleNameLowerCase[ MAX_PATH ];
    CHAR						Letter;
    UINT						Index;
    PLOADER_DATA_TABLE_ENTRY	pModule;
    PPROC_ENV_BLOCK				pPeb = 0;

    if ( ( pPeb = ( PPROC_ENV_BLOCK )__readgsqword( 0x60 ) ) == NULL )
        return NULL;

    for ( 
		pModule = ( PLOADER_DATA_TABLE_ENTRY )pPeb->Ldr->InLoadOrderModuleList.Flink; 
		pModule->DllBase != NULL; 
		pModule = ( PLOADER_DATA_TABLE_ENTRY )pModule->InLoadOrderLinks.Flink
	) {
        if ( pModule->BaseDllName.Length && pModule->BaseDllName.Length < MAX_PATH ) 
		{
            for ( Index = 0; Index < pModule->BaseDllName.Length; Index++ ) 
			{
                Letter = ( CHAR )( pModule->BaseDllName.Buffer[ Index ] );
                ModuleNameLowerCase[ Index ] = ( Letter >= 'A' && Letter <= 'Z' && Letter != 0x00 ) ? Letter + 0x20 : Letter;
            }

            ModuleNameLowerCase[ Index++ ] = '\0';
            if ( HashStringA( ModuleNameLowerCase ) == Hash) 
			{
                dbg( "Resolved 0x%0.8X to %s", Hash, ModuleNameLowerCase );
                return ( HMODULE )( pModule->DllBase );
            }
        }
    }
    dbg( "Could not resolve 0x%0.8X to a DLL in the PEB", Hash );
    return NULL;
}

FARPROC GetProcAddressByHash( IN HMODULE hModule, IN DWORD Hash )
{

    PIMAGE_EXPORT_DIRECTORY pExportDir;
	PDWORD					pAddresses, pNames;
	PWORD					pOrdinals;
	PIMAGE_SECTION_HEADER	pSection, pText;
	ULONG_PTR				FunctionAddress;
	HMODULE					hDll;
	ULONG_PTR				Offset;
	INT						j;
	CHAR					ModuleName[ MAX_PATH ] = { 0 }, C;
    ULONG_PTR				Base			= ( ULONG_PTR )hModule;
    PIMAGE_DOS_HEADER		pDos			= ( PIMAGE_DOS_HEADER )Base;
    PIMAGE_NT_HEADERS		pNt				= ( PIMAGE_NT_HEADERS )( Base + pDos->e_lfanew );
	fpLoadLibraryA			LoadLibraryA	= 0;

	if ( pNt->Signature != IMAGE_NT_SIGNATURE ) 
	{
        dbg("NT Siganture mismatch. Got 0x%0.4X, Expected 0x%0.4X", pNt->Signature, IMAGE_NT_SIGNATURE);
        return 0;
    }

	/* Get export directory information */
    pExportDir  = ( PIMAGE_EXPORT_DIRECTORY )( Base + pNt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
    pAddresses  = ( PDWORD )( Base + pExportDir->AddressOfFunctions ),
    pNames      = ( PDWORD )( Base + pExportDir->AddressOfNames );
    pOrdinals   = ( PWORD )( Base + pExportDir->AddressOfNameOrdinals );
    pSection	= IMAGE_FIRST_SECTION( pNt );
    pText		= 0;

	/* Locate text section for forwarded function support */
    for ( unsigned int i = 0; i < pNt->FileHeader.NumberOfSections; i++, pSection++ ) 
	{
        if ( pSection->Characteristics & IMAGE_SCN_MEM_READ && pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE ) 
		{
            pText = pSection;
            break;
        }
    }

	/* Resolve function hash to function address */
    for (unsigned int i = 0; i < pExportDir->NumberOfFunctions; i++) 
	{
        if ( HashStringA( ( PCHAR )( Base + pNames[ i ] ) ) == Hash ) 
		{
            FunctionAddress = Base + pAddresses[ pOrdinals[ i ] ];
            if ( FunctionAddress >= ( Base + pText->SizeOfRawData ) ) // If function is outside of text section, it is a forwarded function
			{
				dbg( "%s is a forwarded function, searching for true location", ( PCHAR )( Base + pNames[ i ] ) );
                Offset = 0, C = 0, j = 0;
                while ( C = *( PCHAR )( FunctionAddress + j ) ) 
				{
                    if ( C == '.' ) 
					{
                        Offset = j + 1;
                        break;
                    }
                    else 
					{
                        ModuleName[ j ] = C;
                    }
                    j++;
                }

				if ( !LoadLibraryA )
					if ( ( LoadLibraryA = ( fpLoadLibraryA )GetProcAddressByHash( GetModuleHandleByHash( KERNEL32 ), LoadLibraryA_Hash ) ) == NULL )
						return NULL;

                if ( ( hDll = LoadLibraryA( ModuleName ) ) == NULL )
                    return NULL;

                FunctionAddress = ( ULONG_PTR )GetProcAddressByHash( hDll, HashStringA( ( PCHAR )( FunctionAddress + Offset ) ) );
            }
            dbg( "Resolved 0x%0.8X to %s at 0x%p", Hash, ( PCHAR )( Base + pNames[ i ] ), ( PVOID )FunctionAddress );
            return ( FARPROC )FunctionAddress;
        }
    }

    dbg("Could not resolve 0x%0.8X to any function address", Hash);
    return 0;
}

# ifdef hc_GLOBAL
BOOL InitApiCalls()
# endif

# ifndef hc_GLOBAL
PHWINAPI InitApiCalls()
# endif
{
	fpNtAllocateVirtualMemory	NtAllocateVirtualMemory;
	NTSTATUS					Status;
	HMODULE*					phModule;
	PVOID*						pFunction;
	INT							TotalFunctions			= 0;
	SIZE_T						RegionSize				= sizeof( HWINAPI );
	DWORD						ModuleHashes[ MODULES ] = { MODULE_HASHES },
								FunctionHashes[]		= { FUNCTION_HASHES };
# ifndef hc_GLOBAL
	PHWINAPI					hc_API_VAR_NAME			= 0;
# endif

	/* Step 1; Locate NtAllocateVirtualMemory & allocate memory to hold the windows api structure */
	dbg( "Allocating memory for win32 api structure" );
	if ( ( NtAllocateVirtualMemory = ( fpNtAllocateVirtualMemory )GetProcAddressByHash( GetModuleHandleByHash( NTDLL ), NtAllocateVirtualMemory_Hash ) ) == NULL )
	{
		dbg( "Could not find NtAllocateVirtualMemory" );
		return FALSE;
	}
	if ( ( Status = NtAllocateVirtualMemory( ( HANDLE )-1, &hc_API_VAR_NAME, 0, &RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) ) != NT_SUCCESS )
	{
		dbg( "Memory allocation failed with error: 0x%0.8X", Status );
		return FALSE;
	}
	
	/* Step 2; get handles to necessary dlls */
	dbg( "Acquiring module handles" );
	phModule = ( HMODULE* ) &( hc_API_VAR_NAME->Modules );
	for ( unsigned int i = 0; i < sizeof( ModuleHashes ) / sizeof( DWORD ); i++ )
	{
		if ( ( *phModule = GetModuleHandleByHash( ModuleHashes[ i ] ) ) == NULL )
		{
			dbg( "Could not locate a handle for 0x%0.8X from the peb. Initialization failed.", ModuleHashes[ i ] );
			return FALSE;
		}
		phModule++;
	}
	
	/* Step 3; Resolve function address to pointers */
	dbg( "Populating function addresses" );
	pFunction = ( PVOID* ) &( hc_API_VAR_NAME->Kernel32 );
	POPULATE_FUNCTIONS( Kernel32 )
	POPULATE_FUNCTIONS( Ntdll )
	
	dbg( "Successfully initialized api call structure. Structure memory location: %p", hc_API_VAR_NAME );

# ifdef hc_GLOBAL
	return TRUE;
# endif
# ifndef hc_GLOBAL
	return hc_API_VAR_NAME;
# endif
}
