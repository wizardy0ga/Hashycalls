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
# pragma once
# include <windows.h>

/* ------------------------- Macros ------------------------- */
// --- Control
# define hc_GLOBAL					// Enable globally available api, requires global variables
# define hc_API_VAR_NAME hWin32		// A name for the api structure variable to be used in your code

// --- DLL Hashes
# define hc_Kernel32	0x4790B670
# define hc_Ntdll	0xD3171196

// --- Functions Hashes
# define hc_CreateToolhelp32Snapshot 0x282927D6
# define hc_Process32FirstW 0x744FC297
# define hc_Process32NextW 0xB898BFF4
# define hc_OpenProcess 0x46009A7
# define hc_VirtualAllocEx 0x6F41E3BB
# define hc_VirtualProtectEx 0x1ED2BC55
# define hc_WriteProcessMemory 0x2898B06F
# define hc_CreateRemoteThread 0x990AB52A
# define hc_WaitForSingleObject 0x4A03E19D
# define hc_CloseHandle 0x14CB9482
# define hc_wcscmp 0xABC1FE9D

// --- Functions
# define EXEC( Module, Function ) hc_API_VAR_NAME->Module.Function

/* ----------------------- Structures ----------------------- */
typedef struct 
{
	struct
	{
		HMODULE Kernel32;
		HMODULE Ntdll;
	}
	Modules;

	struct
	{
		HANDLE ( WINAPI* CreateToolhelp32Snapshot ) ( DWORD dwFlags, DWORD th32ProcessID );
		BOOL ( WINAPI* Process32FirstW ) ( HANDLE hSnapshot, LPVOID lppe );
		BOOL ( WINAPI* Process32NextW ) ( HANDLE hSnapshot, LPVOID lppe );
		HANDLE ( WINAPI* OpenProcess ) ( DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId );
		LPVOID ( WINAPI* VirtualAllocEx ) ( HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect );
		BOOL ( WINAPI* VirtualProtectEx ) ( HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect );
		BOOL ( WINAPI* WriteProcessMemory ) ( HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten );
		HANDLE ( WINAPI* CreateRemoteThread ) ( HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId );
		DWORD ( WINAPI* WaitForSingleObject ) ( HANDLE hHandle, DWORD dwMilliseconds );
		BOOL ( WINAPI* CloseHandle ) ( HANDLE hObject );
	}
	Kernel32;

	struct
	{
		int ( WINAPI* wcscmp ) ( const wchar_t *string1, const wchar_t *string2 );
	}
	Ntdll;
}
HWINAPI, *PHWINAPI;

/* ------------------------- Externals ------------------------- */
# ifdef hc_GLOBAL
extern PHWINAPI hc_API_VAR_NAME;
# endif

/* ------------------------- Functions ------------------------- */
# ifdef hc_GLOBAL
/*
	@brief 
		Initializes the global win32 api structure. This structure contains all of the
		function addresses, is used to execute the functions.

	@return BOOL
		True if initialization is successful else False
*/
BOOL InitApiCalls();
# endif

# ifndef hc_GLOBAL
/*
	@brief 
		Initializes a win32 api structure. This structure contains all of the function
		addresses, is used to execute the functions.

	@return PHWINAPI
		A pointer to the win32 api structure
*/
PHWINAPI InitApiCalls();
# endif

/*
	@brief
		Locates the address of a function in a loaded module / dll

	@param[in]  HMODULE hModule
		A handle to the module / dll to search

	@param[out] DWORD Hash
		A has of the function name to lookup

	@return FARPROC || NULL
		An address of the function if found or null if not found
*/
FARPROC GetProcAddressByHash( IN HMODULE hModule, DWORD Hash );

/*
	@brief 
		Searches the PEB for a handle to loaded module

	@param[out] DWORD Hash
		A hash of module name to search for

	@return HMODULE || NULL
		A handle to the module if found or null if not found
*/
HMODULE GetModuleHandleByHash( IN DWORD Hash );