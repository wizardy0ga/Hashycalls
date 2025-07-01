# pragma once
# include <windows.h>

/* ------------------------- Macros ------------------------- */
// --- Control
# define hc_GLOBAL					// Enable globally available api, requires global variables
# define hc_API_VAR_NAME hWin32		// A name for the api structure variable to be used in your code

// --- DLL Hashes
# define hc_Kernel32	0x491A6140 
# define hc_User32		0xDF11924E

// --- Functions Hashes
# define hc_GetCurrentProcessId     0x0B5FE8B9
# define hc_MessageBoxA				0x69CA3A2F

// --- Functions
# define EXEC( Module, Function ) hc_API_VAR_NAME->Module.Function

/* ----------------------- Structures ----------------------- */
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
		INT	( WINAPI* MessageBoxA ) ( HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType );
	}
	User32;
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