<p align=center>
    <img src=./Img/memez.png> </img>
</p>

## About
Hashycalls is a program which automates the win32 API hashing code development process. With hashycalls, a developer can simply provide the names of the functions to hash & hashycalls will produce the code required to resolve / use the function calls in the program. This code is stored in a headerfile which can be imported into any part of a C program.

Hashycalls provides the following code pieces for the developer:
- Function hash macros
- Function dll hash macros
- Function prototype definitions
- Hash resolution functions
- Various utility functions

Each header file generated will have randomized hashes generated for each function address to resolve. Changing the hashes in a program is simply done by generating a new hashycalls header file & swapping the old header file with it.

> ![IMPORTANT]
> HashyCalls only supports the x64 architecture in its current version.

## Usage

Hashycalls can produce two kinds of templates. The base template includes the hashes & functions necessary to resolve the hashes into function addresses. The second template creates a global api structure which is accessible anywhere in the program & automates the resolution of each function listed in the structure.

### Script (hashycalls.py)

Use the [hashycalls.py](/HashyCalls.py) script to generate the templates. The arguments for the script have been listed below.

###### Input Arguments (mutually exclusive)
| Argument | Description |
| - | - |
| --file FILE_PATH | A path to a text file containing the api calls to hash. API calls should be seperated by new line in file text. |
| --apicalls FUNC_1 FUNC_2 FUNC_3 ETC | A list of api calls to hash.

###### Optional Arguments
| Argument | Description |
| - | - |
| -o, --outfile FILE_NAME| A name for the output header file. |
| -a, --algo ALGO | The hashing algorithm to use when hashing & resolving api calls. Defaults to sdbm. |
| -ga, --global_api | Include code to create a globally accessible hashed API structure. |

##### Examples
###### Create base template using djb2 algorithm with api calls listed in file
`python hashycalls.py --file api_calls.txt --algo djb2`
###### Create global template using API calls specified at the command line
`python hashycalls.py --apicalls VirtualAllocEx CreateRemoteThread WriteProcessMemory WaitForSingleObject -ga`

#### Hashing Algorithms
At this time, there are two hashing algorthims available for use, **sdbm** & **djb2**. Specify either of these algorithms with the `-a, --algo` argument.

### Templates

#### Base Templates
The base template provides the necessary code for the developer to resolve the function calls themselves. This template is intended for position independent code & other scenarios where a globally accessible api structure is not necessary.

#### Global Templates
The global template provides all of the code in the base template with additional code to create and automate the resolution of a global api structure. This makes it easier for the developer to access the hashed function address through the **HashedAPI** global variable. This template can not be used with any position independent code due to its dependency on a global variable.

### Exported Functions (Both Templates)

#### Hash Resolution Functions
| Name |  Description | Prototype |
| - | - | - |
| GetModuleHandleByHash | Get a handle to a dll that is already loaded in the process. Returns NULL if none is found. This function expects a hash from a lowercase version of the module name. | HMODULE GetModuleHandleByHash(IN DWORD Hash) | 
| GetProcAddressByHash | Retrieve the address of a function from a dll by its hash | FARPROC GetProcAddressByHash(IN HMODULE hModule, IN DWORD Hash) | 

#### Utility Functions
| Name |  Description | Prototype |
| - | - | - |
| [StringLengthA](https://github.com/vxunderground/VX-API/blob/main/VX-API/StringLength.cpp) | Get the length of an ANSI character string | SIZE_T StringLengthA(_In_ LPCSTR String) |
| WCharToChar | Convert a wide character string to ANSI | VOID WCharToChar(OUT PCHAR Dest, IN PWCHAR Source) |
| [StringLengthW](https://github.com/vxunderground/VX-API/blob/main/VX-API/StringLength.cpp) | Get the length of a wide character string | SIZE_T StringLengthW(LPCWSTR String) |
| [StringCopyA](https://github.com/vxunderground/VX-API/blob/main/VX-API/StringCopy.cpp) | Copy a string to another buffer | PCHAR StringConcatA(_Inout_ PCHAR String, _In_ LPCSTR String2) |
| ToLower | Convert an ANSI string to lowercase | VOID ToLower(IN PCHAR String) |

### Exported Macros (Both Templates)
| Definition | Description |
| - | - |
| LOCATE_KERNEL32_FUNCTION(ApiCallName) | Locate a function in kernel32
| LOCATE_KERNELBASE_FUNCTION(ApiCallName) | Locate a function in kernelbase
| LOCATE_NTDLL_FUNCTION(ApiCallName) | Locate a function in ntdll

The macros are designed to accept the name of the function to resolve. The macro will return the function variable with an underscore prepended -> LOCATE_KERNEL32_FUNCTION(VirtualAlloc) would return the VirtualAlloc function in the variable **VirtualAlloc_**. These functions are intended to reduce repitition between GetProcAddressByHash & GetModuleAddressByHash usage. 

### Exported Functions (Global Template)
The argument `-ga` will produce a template which contains the code for creating a globally accessible hashed api call structure. This automates the resolution process & reduces the amount of calls to GetProcAddressByHash & GetModuleHandleByHash however it can't be used with position independent code as it requires access to global variables.

| Name |  Description | Prototype |
| - | - | - |
| GetEnvVarByHash | Locate an environment variable from the PEB by its hash. | SIZE_T GetEnvVarByHash( IN DWORD Hash, OUT PCHAR OutBuffer)
| LoadDllFromSystem32ByHash | Load a DLL into the process from system32 by its file name hash. File name should be hashed from lowercase file name. | HMODULE LoadDllFromSystem32ByHash(IN DWORD Hash)
| InitApiCalls | Initialize the global api structure, **HashedAPI**. | BOOL InitApiCalls()

### Exported Macros (Global Template)
| Definition | Description |
| - | - |
| GET_FUNCTION_CALL(FunctionName) | Resolves a function from **HashedAPI** structure into variable using the underscore syntax.

### Code Examples

#### Base Template

When using the base template, the developer can use the LOCATE* function macros to resolve the api calls within the block of code. At this time, the developer is restricted to functions in either ntdll, kernelbase or kernel32. This is subject to change in a future update.

```C
#include "hashycalls.h"
#include <stdio.h>

// MSFvenom calc shellcodez
const byte calc[] = {
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

int main() {

    /* Locate the function from the dll */
	LOCATE_KERNEL32_FUNCTION(VirtualAlloc);
	LOCATE_KERNEL32_FUNCTION(WriteProcessMemory);
	LOCATE_KERNEL32_FUNCTION(CreateRemoteThread);
    LOCATE_KERNEL32_FUNCTION(WaitForSingleObject);

	PVOID pBase = VirtualAlloc_(NULL, sizeof(calc), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pBase) {
		printf("Error virtual alloc: %d\n", GetLastError());
		return -1;
	}

	size_t BytesWritten = 0;
	if (!(WriteProcessMemory_((HANDLE)-1, pBase, calc, sizeof(calc), &BytesWritten))) {
		printf("Failed to write memory. error: %d\n", GetLastError());
		return -1;
	}

	HANDLE hThread = CreateRemoteThread_((HANDLE)-1, 0, 0, (LPTHREAD_START_ROUTINE)pBase, 0, 0, 0);
	if (!hThread) {
		printf("Failed to make thread. error: %d\n", GetLastError());
		return -1;
	}
	printf("created new thread\n");
	WaitForSingleObject_(hThread, INFINITE);

	printf("done\n");
	return 0;
}
```

#### Global Template

When using the global template, the developer must call the **initApiCalls()** function to resolve the API_CALL_LIST structure. This function resolves all of the specified functions hashes into addresses which are stored in a structure with the variable name **HashedAPI**. This function only needs to be called once, prior to using any of the hashed function calls.

To access these functions, the developer can call the **GET_FUNCTION_CALL** macro which resolves the function hash into an address found in the structure.

```C
#include "hashycalls.h"
#include <stdio.h>

// MSFvenom calc shellcodez
const byte calc[] = {
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

int main() {

	if (!(InitApiCalls())) {
		return -1;
	}

    /* Get the function calls from the HashedAPI structure */
	GET_FUNCTION_CALL(VirtualAlloc);
	GET_FUNCTION_CALL(WriteProcessMemory);
	GET_FUNCTION_CALL(CreateRemoteThread);
    GET_FUNCTION_CALL(WaitForSingleObject);

	PVOID pBase = VirtualAlloc_(NULL, sizeof(calc), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pBase) {
		printf("Error virtual alloc: %d\n", GetLastError());
		return -1;
	}

	size_t BytesWritten = 0;
	if (!(WriteProcessMemory_((HANDLE)-1, pBase, calc, sizeof(calc), &BytesWritten))) {
		printf("Failed to write memory. error: %d\n", GetLastError());
		return -1;
	}

	HANDLE hThread = CreateRemoteThread_((HANDLE)-1, 0, 0, (LPTHREAD_START_ROUTINE)pBase, 0, 0, 0);
	if (!hThread) {
		printf("Failed to make thread. error: %d\n", GetLastError());
		return -1;
	}
	printf("created new thread\n");

	WaitForSingleObject_(hThread, INFINITE);

	printf("done\n");
	return 0;
}
```

## Credits

- [reverseame](https://github.com/reverseame) for their windows api data set. It has been very useful. Can't thank them enough.