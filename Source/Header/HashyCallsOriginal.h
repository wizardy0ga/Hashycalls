#pragma once
#include <windows.h>
#include <stdio.h>

#define GLOBAL_ARCHITECTURE

#define SEED_HASH 8888

/* DLL Hashes */
#define KERNEL32 0xA52DE12A         // kernel32.dll
#define NTDLL 0xCE561B5C            // ntdll.dll
#define KERNELBASE 0xF6D4FD9C       // kernelbase.dll

/* Internal function hashes */
#define LoadLibraryA_Hash 0xF4DAB6A4     // LoadLibraryA
#define FindFirstFileA_Hash 0x4CE39F26  // FindFirstFileA
#define FindNextFileA_Hash 0xEF6B1DC1   // FindNextFileA
#define NtAllocateVirtualMemory_Hash 0x882B79D1
#define AddRefActCtx_Hash 0x28CE98FF

typedef NTSTATUS(NTAPI* fpNtAllocateVirtualMemory)(
    HANDLE    ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
);

typedef void(WINAPI* fpAddRefActCtx)(
  HANDLE hActCtx
);

/* Hashed strings */
#define WINDIR 0xFCB19529           // windir
#define SYSTEM32 0x8CDECC66         // system32

/* testing */
#define SH_CHANGE_NOTIFY_REGISTER 0x7D8FCBE9
#define SHELL32 0xE2D33CAD

#define LOCATE_KERNEL32_FUNCTION(ApiCallName) fp##ApiCallName ApiCallName##_ = (fp##ApiCallName)GetProcAddressByHash(GetModuleHandleByHash(KERNEL32), ApiCallName##_Hash); \
if (!ApiCallName##_) { return FALSE; }\

#define LOCATE_KERNELBASE_FUNCTION(ApiCallName) fp##ApiCallName ApiCallName##_ = (fp##ApiCallName)GetProcAddressByHash(GetModuleHandleByHash(KERNELBASE), ApiCallName##_Hash); \
if (!ApiCallName##_) { return FALSE; }\

#define LOCATE_NTDLL_FUNCTION(ApiCallName) fp##ApiCallName ApiCallName##_ = (fp##ApiCallName)GetProcAddressByHash(GetModuleHandleByHash(NTDLL), ApiCallName##_Hash); \
if (!ApiCallName##_) { return FALSE; }\

#define LOCATE_FUNCTION(ApiCallName, ModuleHash) fp##ApiCallName ApiCallName##_ = (fp##ApiCallName)GetProcAddressByHash(GetModuleHandleByHash(ModuleHash), ApiCallName##_Hash); \
if (!ApiCallName##_) { return FALSE; }\


/* Structures */
typedef struct _UNICODE_STRING_
{
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING_, * PUNICODE_STRING_;

typedef struct _LOADER_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING_ FullDllName;
    UNICODE_STRING_ BaseDllName;
} LOADER_DATA_TABLE_ENTRY, * PLOADER_DATA_TABLE_ENTRY;

typedef struct _PEB_LOADER_DATA
{
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
} PEB_LOADER_DATA, * PPEB_LOADER_DATA;

typedef struct _CURDIR
{
    UNICODE_STRING_ DosPath;
    HANDLE Handle;
} CURDIR, * PCURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;
    CURDIR CurrentDirectory;
    UNICODE_STRING_ DllPath;
    UNICODE_STRING_ ImagePathName;
    UNICODE_STRING_ CommandLine;
    PVOID Environment;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PROC_ENV_BLOCK
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LOADER_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
} PROC_ENV_BLOCK, * PPROC_ENV_BLOCK;

/* Function prototypes */
typedef HMODULE(WINAPI* fpLoadLibraryA)( LPCSTR lpLibFileName );
typedef HANDLE(WINAPI* fpFindFirstFileA)( LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData );
typedef BOOL(WINAPI* fpFindNextFileA)( HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData );

/* Utility functions */
SIZE_T StringLengthA(_In_ LPCSTR String)
{
    LPCSTR String2;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}

VOID WCharToChar(PCHAR Dest, PWCHAR Source) {
    while (TRUE) {
        if (!(*Dest++ = (CHAR)*Source++)) {
            break;
        }
    }
}

SIZE_T StringLengthW(_In_ LPCWSTR String)
{
    LPCWSTR String2;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}

PCHAR StringCopyA(_Inout_ PCHAR String1, _In_ LPCSTR String2)
{
    PCHAR p = String1;

    while ((*p++ = *String2++) != 0);

    return String1;
}

PCHAR StringConcatA(_Inout_ PCHAR String, _In_ LPCSTR String2)
{
    StringCopyA(&String[StringLengthA(String)], String2);

    return String;
}

VOID ToLower(PCHAR String) {
    int Index = 0;
    char Letter = 0;
    for (Index = 0; Index < StringLengthA(String); Index++) {
        Letter = (char)String[Index];
        String[Index] = (Letter >= 'A' && Letter <= 'Z') ? Letter + 0x20 : Letter;
    }
}

DWORD HashString(PCHAR String) {
    ULONG Hash = SEED_HASH;
    INT c;

    while (c = *String++)
        Hash = c + (Hash << 6) + (Hash << 16) - Hash;

    return Hash;
}

/* API Handeling functions */

/*
    @brief Get a handle to a dll that is already loaded in this process.

    @param Hash - A hash of the dll name to search for.

    @returns Returns a handle to the target dll or null if not found.
*/
HMODULE GetModuleHandleByHash(IN DWORD Hash) {

	CHAR ModuleNameLowerCase[MAX_PATH];
	CHAR Letter = 0;
	UINT Index = 0;
    PLOADER_DATA_TABLE_ENTRY pModule = 0;
    PPROC_ENV_BLOCK pPeb = (PPROC_ENV_BLOCK)__readgsqword(0x60);
    if (!pPeb) {
        return NULL;
    }
    
    for (pModule = (PLOADER_DATA_TABLE_ENTRY)pPeb->Ldr->InLoadOrderModuleList.Flink; pModule->DllBase != NULL; pModule = (PLOADER_DATA_TABLE_ENTRY)pModule->InLoadOrderLinks.Flink) {
        if (pModule->BaseDllName.Length && pModule->BaseDllName.Length < MAX_PATH) {
            for (Index = 0; Index < pModule->BaseDllName.Length; Index++) {
                Letter = (CHAR)(pModule->BaseDllName.Buffer[Index]);
                ModuleNameLowerCase[Index] = (Letter >= 'A' && Letter <= 'Z' && Letter != 0x00) ? Letter + 0x20 : Letter;
            }
            ModuleNameLowerCase[Index++] = '\0';
            if (HashString(ModuleNameLowerCase) == Hash) {
                return (HMODULE)(pModule->DllBase);
            }
        }
    }
    return NULL;
}

/*
    @brief Get a function address from a dll using a hash of the functions name.

    @param hModule - A handle to the dll containing the target function.
    @param Hash    - A hash of the target function name.

    @return Returns the functions address or NULL if not found.
*/
FARPROC GetProcAddressByHash(IN HMODULE hModule, IN DWORD Hash) {
    
    /* Check NT Header */
    ULONG_PTR         Base = (ULONG_PTR)hModule;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)Base;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(Base + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }
    
    /* Get function stuff from export directory */
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(Base + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PDWORD   pAddresses  = (PDWORD)(Base + pExportDir->AddressOfFunctions),
             pNames      = (PDWORD)(Base + pExportDir->AddressOfNames);
    PWORD    pOrdinals   = (PWORD)(Base + pExportDir->AddressOfNameOrdinals);
    
    /* Get address of .text section for forwarded function checks */
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt),
                          pText = 0;
    for (unsigned int i = 0; i < pNt->FileHeader.NumberOfSections; i++, pSection++) {
        if (pSection->Characteristics & IMAGE_SCN_MEM_READ && pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            pText = pSection;
            break;
        }
    }

    /* Locate function in the module */
    for (unsigned int i = 0; i < pExportDir->NumberOfFunctions; i++) {
        if (HashString((PCHAR)(Base + pNames[i])) == Hash) {
            ULONG_PTR FunctionAddress = Base + pAddresses[pOrdinals[i]];

            /* If name location is outside of .text section, function is assumed forwarded. sure hope it's in the rdata section lol. */
            if (FunctionAddress >= (Base + pText->SizeOfRawData)) {

                CHAR ModuleName[MAX_PATH] = { 0 };
                ULONG_PTR Offset = 0;
                CHAR C = 0;
                int j = 0;

                /* Copy module name to buffer & collect offset to function name */
                while (C = *(PCHAR)(FunctionAddress + j)) {
                    if ( C == '.' ) {
                        Offset = j + 1;
                        break;
                    }
                    else {
                        ModuleName[j] = C;
                    }
                    j++;
                }

                LOCATE_KERNEL32_FUNCTION(LoadLibraryA);

                HMODULE hModule = LoadLibraryA_(ModuleName);
                if (!hModule) {
                    return NULL;
                }

                FunctionAddress = (ULONG_PTR)GetProcAddressByHash(hModule, HashString((PCHAR)(FunctionAddress + Offset)));
            }
            return (FARPROC)FunctionAddress;
        }
    }

    return 0;
}

#ifdef GLOBAL_ARCHITECTURE

#define GET_FUNCTION_CALL(FunctionName) fp##FunctionName FunctionName##_ = (fp##FunctionName)(&HashedAPI)->##FunctionName.Address

typedef LPVOID(WINAPI* fpVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);

typedef struct _API_CALL {
    DWORD Hash;
    PVOID Address;
    DWORD ModuleHash;
    PVOID hModule;
} API_CALL, * PAPI_CALL;

typedef struct _API_CALL_LIST {
    API_CALL CreateRemoteThread;
    API_CALL VirtualAlloc;
    API_CALL VirtualProtect;
    API_CALL SHChangeNotifyRegister;
    API_CALL BaseRegFlushKey;
    BOOL Initialized;
} API_CALL_LIST, * PAPI_CALL_LIST;

API_CALL_LIST HashedAPI = {
    .CreateRemoteThread.Hash = 0x617A28E4,
    .CreateRemoteThread.ModuleHash = KERNEL32,
    .VirtualAlloc.Hash = 0x4F80A102,
    .VirtualAlloc.ModuleHash = KERNEL32,
    .VirtualProtect.Hash = 0x9F90E99C,
    .VirtualProtect.ModuleHash = KERNEL32,
    .SHChangeNotifyRegister.Hash = SH_CHANGE_NOTIFY_REGISTER,
    .SHChangeNotifyRegister.ModuleHash = SHELL32,
    .BaseRegFlushKey.ModuleHash = 0x47CF92D4,
    .BaseRegFlushKey.Hash = 0x4EAB0266
};

/*
    @brief Get the value of an environment variable via the hashed variable name.

    @param Hash - A hash of the variable name who's value will be retrieved.

    @param OutBuffer - A buffer to write the value of the variable to.
*/
SIZE_T GetEnvVarByHash( IN DWORD Hash, OUT PCHAR OutBuffer) {
    PBYTE pEnvironment = ((PPROC_ENV_BLOCK)__readgsqword(0x60))->ProcessParameters->Environment,
        pTmp;
    SIZE_T StringSize;
    CHAR VarNameBufferW[MAX_PATH];
    CHAR VarNameBufferA[MAX_PATH];
    INT Index = 0;

    while (TRUE) {
        if ((StringSize = StringLengthW((LPCWSTR)pEnvironment)) != 0) {
            pTmp = pEnvironment;
            Index = 0;
            
            /* Locate the name of the environment variable. Stop copying to buffer when '=' sign is reached. */
            while (*pTmp != '=') {
                VarNameBufferW[Index] = *pTmp++;
                Index++;
            }
            VarNameBufferW[Index] = '\0';
            WCharToChar(VarNameBufferA, (PWCHAR)VarNameBufferW);
           
            if (HashString(VarNameBufferA) == Hash) {
                WCharToChar(OutBuffer, (PWCHAR)(pEnvironment + Index + sizeof(WCHAR)));
                return StringLengthA(OutBuffer);
            }
            
        }
        else {
            break;
        }
        pEnvironment += (StringSize * sizeof(WCHAR)) + sizeof(WCHAR);
    }

    return FALSE;
}

/*
    @brief 
        Loads a dll from system32 using the hash of the dll file name.

    @param Hash - A hash of the dll file to be loaded in the process

    @return Returns a handle to the module or NULL if the dll was not loaded. 
*/
HMODULE LoadDllFromSystem32ByHash(IN DWORD Hash) {

    WIN32_FIND_DATAA FileData = { 0 };
    HANDLE hFile;
    CHAR DirSearchString[MAX_PATH];
    BOOL System32Found = FALSE;

    /* Get required functions */
    LOCATE_KERNEL32_FUNCTION(LoadLibraryA);
    LOCATE_KERNEL32_FUNCTION(FindFirstFileA);
    LOCATE_KERNEL32_FUNCTION(FindNextFileA);
    
    /* Create the search string c:\windows\* */
    SIZE_T VarSize = GetEnvVarByHash(WINDIR, DirSearchString);
    if (VarSize == 0 || VarSize > MAX_PATH)
        return NULL;
    StringConcatA(DirSearchString, "\\*");

    /* Locate System32 directory & build search string -> C:\Windows\System32\* */
    if ((hFile = FindFirstFileA_(DirSearchString, &FileData)) == INVALID_HANDLE_VALUE) {
        return NULL;
    }
    do 
    {
        if (HashString(FileData.cFileName) == SYSTEM32) 
        {
            DirSearchString[StringLengthA(DirSearchString) - 1] = '\0'; /* C:\Windows\* -> C:\Windows */
            StringConcatA(DirSearchString, FileData.cFileName);         /* C:\Windows\System32        */
            StringConcatA(DirSearchString, "\\*");                      /* C:\Windows\System32\*      */
            System32Found = TRUE;
        }
    } 
    while (FindNextFileA_(hFile, &FileData) != 0 || System32Found != TRUE);

    if (!System32Found)
        return NULL;

    /* Locate the dll in the system32 directory & load it into the process */
    if ((hFile = FindFirstFileA_(DirSearchString, &FileData)) == INVALID_HANDLE_VALUE) {
        return NULL;
    }
    do {
        ToLower(FileData.cFileName);
        if (HashString(FileData.cFileName) == Hash) {
            return LoadLibraryA_(FileData.cFileName);
        }
    } while (FindNextFileA_(hFile, &FileData) != 0);

    return NULL;
}

/*
    @brief Populate the global api structure with target function addresses. Required prior to using the structure.

    @returns True if full resolution was successful, false if anything else.
*/
BOOL InitApiCalls() {
    PAPI_CALL pApiCall = (PAPI_CALL)&HashedAPI;
    if (!(&HashedAPI)->Initialized) {
        for (int i = 0; i < (sizeof(API_CALL_LIST) / sizeof(API_CALL)); i++) {
            if ((pApiCall->hModule = GetModuleHandleByHash(pApiCall->ModuleHash)) == NULL) {
                if ((pApiCall->hModule = LoadDllFromSystem32ByHash(pApiCall->ModuleHash)) == NULL) {
                    return FALSE;
                }
            }
            if ((pApiCall->Address = GetProcAddressByHash(pApiCall->hModule, pApiCall->Hash)) == NULL) {
                return FALSE;
            }
            (ULONG_PTR)pApiCall += sizeof(API_CALL);
        }
        (&HashedAPI)->Initialized = TRUE;
    }
    return TRUE;
}
#endif