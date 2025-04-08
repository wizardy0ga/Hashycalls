import argparse
import random
import json
import sys
import os

SCRIPT_VERSION = "1.2.0"
TEMPLATE_VERSION = "1.0.0"

GREEN = "\033[1;32m"
PURPLE = "\033[1;35m"
WHITE = "\033[1;37m"
CYAN = "\033[1;36m"
RED = "\033[1;31m"
END = "\033[0m"

# Mandatory functions required by header file library
INTERNAL_FUNCTIONS = [
    "LoadLibraryA",
    "FindFirstFileA",
    "FindNextFileA"
]

# Default dll strings to be hashed
DLL_HASHES = [
    "kernel32.dll",
    "ntdll.dll",
    "kernelbase.dll"
]

# Required for env variables & directory searches
STRING_HASHES = [
    "windir",
    "System32"
]

DEFAULT_OUTFILE_NAME = "hashycalls.h"

BANNER = f"""{GREEN}_  _ ____ ____ _  _ _   _    ____ ____ _    _    ____ 
|__| |__| [__  |__|  \\_/  __ |    |__| |    |    [__  
|  | |  | ___] |  |   |      |___ |  | |___ |___ ___] 

{WHITE}A win32 api hashing utility for C{END}
"""

with open('source/data/winapi.json') as windows_api_data_set:
    WINDOWS_API_INFO = json.loads(windows_api_data_set.read())

def _print(msg: str) -> None:
    print(f"{WHITE}[ {GREEN}> {WHITE}] {msg}")

def get_function_info(function_name: str) -> dict or False:
    function_info = {}
    
    # Verify the function exists
    if function_name not in WINDOWS_API_INFO.keys():
        return False
    
    # Add the functions dll
    function_info['dll'] = WINDOWS_API_INFO[function_name]['dll'].lower()

    # Create function prototype & add to return object
    prototype = f"typedef {WINDOWS_API_INFO[function_name]['return_type']}(WINAPI* fp{function_name})("
    parameter_count = 1
    for parameter in WINDOWS_API_INFO[function_name]['arguments']:
        prototype += f"{parameter['type']} {parameter['name']}"
        if parameter_count != len(WINDOWS_API_INFO[function_name]['arguments']):
            prototype += ", "
        parameter_count += 1
    prototype += ");"
    function_info['prototype'] = prototype

    return function_info

def sdbm(seed: int, string: str) -> int:
    Hash = seed
    for x in list(string):
        Hash = ord(x) + (Hash << 6) + (Hash << 16) - Hash
    return hex(Hash & 0xFFFFFFFF).upper().replace('X', 'x')

def djb2(seed: int, string: str):
    hash = seed
    for i in string:
        hash = ((hash << 5) + hash) + ord(i)
    return hex(hash & 0xFFFFFFFF).upper().replace('X', 'x')

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    input_mutex_group = parser.add_mutually_exclusive_group()
    parser.add_argument('-a', '--algo', choices=['djb2', 'sdbm'], default='sdbm', help='Hashing algorithm to use when hashing the windows apis')
    parser.add_argument('-ga', '--global_api', action='store_true', help='Include code for hashing API globally, allowing entire program to access hashed API calls')
    parser.add_argument('-o', '--outfile', type=str, help=f'A name for the header file. Defaults to {DEFAULT_OUTFILE_NAME}', default=DEFAULT_OUTFILE_NAME)
    parser.add_argument('-s', '--seed', type=int, help='A seed for the hash. Defaults to a random int', default=random.randint(1000, 10000))
    input_mutex_group.add_argument('--file', type=str, help='Path to a file containing the api calls to hash')
    input_mutex_group.add_argument('--apicalls', nargs='+', type=str, help='A list of api calls to hash. Seperate each call with a space.')
    args = parser.parse_args()

    print(BANNER)
    for pair in [{'Author': 'wizardy0ga'}, {'Script Version': SCRIPT_VERSION}, {'C Template Version': TEMPLATE_VERSION}]:
        for key, value in pair.items():
            print(f"{WHITE}[{CYAN}+{WHITE}] {key}: {value}")
    print("\n")

    # Import API calls from user
    if not args.file:
        user_api_call_import = args.apicalls
    else:
        try:
            with open(args.file, 'r') as file:
                user_api_call_import = file.read().split('\n')
        except FileNotFoundError:
            _print(f"{RED}Could not find the file {WHITE}{args.file}")
            exit(1)
    
    if user_api_call_import == None:
        _print(f"{RED}No function calls were specified. Specify a list of function calls with {WHITE}--apicalls{RED} or the path of a file containing the api calls with {WHITE}--file{RED}.{END}")
        exit(1)
    
    for function in user_api_call_import:
        if function in INTERNAL_FUNCTIONS:
            user_api_call_import.remove(function)
            _print(f"{GREEN}{function}{WHITE} function is included by default. Omitting.")
    #[user_api_call_import.remove(function) for function in user_api_call_import if function in INTERNAL_FUNCTIONS]

    for function in user_api_call_import:
        if function not in WINDOWS_API_INFO.keys():
            _print(f"{RED}Failed to get function information for {WHITE}{function}{RED}. Please add this function to the data set at {WHITE}source/data/winapi.json{END}")
            exit(1)

    _print(f"Imported {GREEN}{len(user_api_call_import)}{WHITE} function calls{END}")

    info_header = f"/*\n\tGenerated with hashycalls script version {SCRIPT_VERSION}. Template version is {TEMPLATE_VERSION}\n\tGenerated with the command line: {' '.join(sys.argv)}"
    if args.file:
        info_header += "\n\tImported API Calls:"
        for function_call in user_api_call_import:
            info_header += f"\n\t\t - {function_call}"
    hashy_calls = f"{info_header}\n*/\n#pragma once\n#include <windows.h>\n"

    # Set hashing algorithm
    match args.algo:
        case 'djb2':
            hash_algo = djb2
        case 'sdbm':
            hash_algo = sdbm
    _print(f"Using {GREEN}{args.algo.upper()}{WHITE} hashing algorithm")
    _print(f"Using hash seed {GREEN}{args.seed}")
    hashy_calls += f"\n#define HASH_SEED {args.seed}\n"

    # Internal things required by hashycalls library
    for string in DLL_HASHES:
        hashy_calls += f"#define {string.split('.')[0].upper()} {hash_algo(args.seed, string)}\n"
    for string in STRING_HASHES:
        hashy_calls += f"#define {string.upper()} {hash_algo(args.seed, string)}\n"
    for string in INTERNAL_FUNCTIONS:
        hashy_calls += f"#define {string}_Hash {hash_algo(args.seed, string)}\n"
    hashy_calls += "\n"

    # Create function hash definitions
    for function_call in user_api_call_import:
        _hash = hash_algo(args.seed, function_call)
        hashy_calls += f"#define {function_call}_Hash {_hash}\n"
        _hash = f" -> {_hash}"
        _print(f"Created hash for {GREEN}{function_call}{PURPLE}{_hash.rjust(50 - len(function_call))}{END}")
    hashy_calls += "\n"

    # Add the function prototypes
    prototypes = ""
    for function in user_api_call_import:
        function_info = get_function_info(function)
        prototypes += f"{function_info['prototype']}\n"
    hashy_calls += f"\n{prototypes}\n"

    # Add structure definitions
    with open('source/templates/structures.c') as structure_file:
        hashy_calls += structure_file.read()
    hashy_calls += "\n"

    # Add support macros for developer usage
    with open('source/templates/macros.c') as macro_file:
        hashy_calls += macro_file.read()
    hashy_calls += "\n" 

    # Add string hashing function
    hashy_calls += "\nDWORD HashString(IN PCHAR String) {\n"
    with open(f'source/templates/{args.algo}.c') as hash_function_file:
        hashy_calls += hash_function_file.read()
    hashy_calls += "\n}\n\n"

    # Add remaining functions for api hashing
    with open('source/templates/functions.c') as function_file:
        hashy_calls += function_file.read()
    hashy_calls += "\n"

    # Add support for globally accessible hashed api structure
    if args.global_api:
        _print("Adding code for global hashed api access")

        # Add global structures & macros
        with open('source/templates/globalheader.c') as global_header_file:
            hashy_calls += global_header_file.read()
        hashy_calls += "\n"

        # Build the global api call structure definition according to functions passed by user
        hashy_calls += "typedef struct _API_CALL_LIST {\n"
        for function in user_api_call_import:
            hashy_calls += f"\tAPI_CALL {function};\n"
        hashy_calls += "\tBOOL Initialized;\n} API_CALL_LIST, *PAPI_CALL_LIST;\n\n"

        # Build the global api structure & function prototypes
        hashed_api_structure = "API_CALL_LIST HashedAPI = {\n"
        for function in user_api_call_import:
            function_info = get_function_info(function)
            hashed_api_structure += f"\t.{function}.Hash = {hash_algo(args.seed, function)},\n\t.{function}.ModuleHash = {hash_algo(args.seed, function_info['dll'])},\n"
        hashed_api_structure += "};\n"
        hashy_calls += f"\n{hashed_api_structure}\n"

        # Add functions for global api resolution & access
        with open('source/templates/globalfunctions.c') as global_function_file:
            hashy_calls += global_function_file.read()
        hashy_calls += "\n"

    with open(args.outfile, 'w') as hashy_calls_file:  
        hashy_calls_file.write(hashy_calls)
    
    _print(f"Saved code to {GREEN}{os.path.abspath(args.outfile)}{END}")

    