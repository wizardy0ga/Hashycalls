/*
 * Generated with hashycalls v-2.0.0
 * Template version: 2.0.0
 * Commandline: C:\Users\Admin\Desktop\Repositories\Public\hashycalls\hashycalls\__main__.py --apicalls VirtualAllocEx WriteProcessMemory CreateRemoteThread InternetOpenUrlA InternetReadFile WSAStartup --outdir .\example-output\
 * ID: 04531277-93be-4c89-8740-3689ad258151
 * Using function calls:
 * 	[+] - VirtualAllocEx
 * 	[+] - WriteProcessMemory
 * 	[+] - CreateRemoteThread
 * 	[+] - InternetOpenUrlA
 * 	[+] - InternetReadFile
 * 	[+] - WSAStartup
*/
# pragma once
# include <windows.h>

/* ------------------------- Macros ------------------------- */
// --- Control
// # define hc_GLOBAL					// Enable globally available api, requires global variables
# define hc_API_VAR_NAME hWin32		// A name for the api structure variable to be used in your code

// --- DLL Hashes
# define hc_Kernel32	0xF3B06DD7
# define hc_Wininet	0xAA5F9F61
# define hc_Ws2_32	0x701FA243

// --- Functions Hashes
# define hc_VirtualAllocEx 0x4BAE57A2
# define hc_WriteProcessMemory 0x91FBDD56
# define hc_CreateRemoteThread 0x26DE211
# define hc_InternetOpenUrlA 0xDD78A362
# define hc_InternetReadFile 0xD4937778
# define hc_WSAStartup 0xE379659D

// --- Functions
# define EXEC( Module, Function ) hc_API_VAR_NAME->Module.Function

/* ----------------------- Structures ----------------------- */
typedef struct 
{
	struct
	{
		HMODULE Kernel32;
		HMODULE Wininet;
		HMODULE Ws2_32;
	}
	Modules;

	struct
	{
		LPVOID ( WINAPI* VirtualAllocEx ) ( HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect );
		BOOL ( WINAPI* WriteProcessMemory ) ( HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten );
		HANDLE ( WINAPI* CreateRemoteThread ) ( HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId );
	}
	Kernel32;

	struct
	{
		LPVOID ( WINAPI* InternetOpenUrlA ) ( LPVOID hInternet, LPCSTR lpszUrl, LPCSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext );
		BOOL ( WINAPI* InternetReadFile ) ( LPVOID hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead );
	}
	Wininet;

	struct
	{
		int ( WINAPI* WSAStartup ) ( WORD wVersionRequested, LPWSADATA lpWSAData );
	}
	Ws2_32;
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