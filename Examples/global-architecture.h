/*
    Generated with the command:
    
        python.exe .\hashycalls.py --apicalls VirtualAlloc CreateRemoteThread WriteProcessMemory NtAllocateVirtualMemory --algo sdbm -ga
*/
#pragma once
#include <windows.h>

#define HASH_SEED 1645
#define KERNEL32 0xD62145DF
#define NTDLL 0x5CAC4EE7
#define KERNELBASE 0x757757D1
#define WINDIR 0x8C07995E
#define SYSTEM32 0x45C23DFB
#define LoadLibraryA_Hash 0x25CE1B59
#define FindFirstFileA_Hash 0xCB85F95B
#define FindNextFileA_Hash 0x6005E64C

#define VirtualAlloc_Hash 0x807405B7
#define CreateRemoteThread_Hash 0x27722E19
#define WriteProcessMemory_Hash 0xB700295E
#define NtAllocateVirtualMemory_Hash 0xAD49D6DC

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

typedef HMODULE(WINAPI* fpLoadLibraryA)( LPCSTR lpLibFileName );
typedef HANDLE(WINAPI* fpFindFirstFileA)( LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData );
typedef BOOL(WINAPI* fpFindNextFileA)( HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData );

#define LOCATE_KERNEL32_FUNCTION(ApiCallName) fp##ApiCallName ApiCallName##_ = (fp##ApiCallName)GetProcAddressByHash(GetModuleHandleByHash(KERNEL32), ApiCallName##_Hash); \
if (!ApiCallName##_) { return FALSE; }\

#define LOCATE_KERNELBASE_FUNCTION(ApiCallName) fp##ApiCallName ApiCallName##_ = (fp##ApiCallName)GetProcAddressByHash(GetModuleHandleByHash(KERNELBASE), ApiCallName##_Hash); \
if (!ApiCallName##_) { return FALSE; }\

#define LOCATE_NTDLL_FUNCTION(ApiCallName) fp##ApiCallName ApiCallName##_ = (fp##ApiCallName)GetProcAddressByHash(GetModuleHandleByHash(NTDLL), ApiCallName##_Hash); \
if (!ApiCallName##_) { return FALSE; }\

#define LOCATE_FUNCTION(ApiCallName, ModuleHash) fp##ApiCallName ApiCallName##_ = (fp##ApiCallName)GetProcAddressByHash(GetModuleHandleByHash(ModuleHash), ApiCallName##_Hash); \
if (!ApiCallName##_) { return FALSE; }\


DWORD HashString(IN PCHAR String) {
    ULONG Hash = HASH_SEED;
    INT c;

    while (c = *String++)
        Hash = c + (Hash << 6) + (Hash << 16) - Hash;

    return Hash;
}

SIZE_T StringLengthA(_In_ LPCSTR String)
{
    LPCSTR String2;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}

VOID WCharToChar(OUT PCHAR Dest, IN PWCHAR Source) {
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

VOID ToLower(IN PCHAR String) {
    int Index = 0;
    char Letter = 0;
    for (Index = 0; Index < StringLengthA(String); Index++) {
        Letter = (char)String[Index];
        String[Index] = (Letter >= 'A' && Letter <= 'Z') ? Letter + 0x20 : Letter;
    }
}

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

FARPROC GetProcAddressByHash(IN HMODULE hModule, IN DWORD Hash) {
    
    ULONG_PTR         Base = (ULONG_PTR)hModule;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)Base;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(Base + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }
    
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(Base + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PDWORD   pAddresses  = (PDWORD)(Base + pExportDir->AddressOfFunctions),
             pNames      = (PDWORD)(Base + pExportDir->AddressOfNames);
    PWORD    pOrdinals   = (PWORD)(Base + pExportDir->AddressOfNameOrdinals);
    
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt),
                          pText = 0;
    for (unsigned int i = 0; i < pNt->FileHeader.NumberOfSections; i++, pSection++) {
        if (pSection->Characteristics & IMAGE_SCN_MEM_READ && pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            pText = pSection;
            break;
        }
    }

    for (unsigned int i = 0; i < pExportDir->NumberOfFunctions; i++) {
        if (HashString((PCHAR)(Base + pNames[i])) == Hash) {
            ULONG_PTR FunctionAddress = Base + pAddresses[pOrdinals[i]];

            if (FunctionAddress >= (Base + pText->SizeOfRawData)) {

                CHAR ModuleName[MAX_PATH] = { 0 };
                ULONG_PTR Offset = 0;
                CHAR C = 0;
                int j = 0;

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

#define GET_FUNCTION_CALL(FunctionName) fp##FunctionName FunctionName##_ = (fp##FunctionName)(&HashedAPI)->##FunctionName.Address

typedef struct _API_CALL {
    DWORD Hash;
    PVOID Address;
    DWORD ModuleHash;
    HMODULE hModule;
} API_CALL, * PAPI_CALL;

typedef struct _API_CALL_LIST {
	API_CALL VirtualAlloc;
	API_CALL CreateRemoteThread;
	API_CALL WriteProcessMemory;
	API_CALL NtAllocateVirtualMemory;
	BOOL Initialized;
} API_CALL_LIST, *PAPI_CALL_LIST;


API_CALL_LIST HashedAPI = {
	.VirtualAlloc.Hash = 0x807405B7,
	.VirtualAlloc.ModuleHash = 0xD62145DF,
	.CreateRemoteThread.Hash = 0x27722E19,
	.CreateRemoteThread.ModuleHash = 0xD62145DF,
	.WriteProcessMemory.Hash = 0xB700295E,
	.WriteProcessMemory.ModuleHash = 0xD62145DF,
	.NtAllocateVirtualMemory.Hash = 0xAD49D6DC,
	.NtAllocateVirtualMemory.ModuleHash = 0x5CAC4EE7,
};

typedef LPVOID(WINAPI* fpVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef HANDLE(WINAPI* fpCreateRemoteThread)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
typedef BOOL(WINAPI* fpWriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
typedef NTSTATUS(WINAPI* fpNtAllocateVirtualMemory)(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protectthe);

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

HMODULE LoadDllFromSystem32ByHash(IN DWORD Hash) {

    WIN32_FIND_DATAA FileData = { 0 };
    HANDLE hFile;
    CHAR DirSearchString[MAX_PATH];
    BOOL System32Found = FALSE;

    LOCATE_KERNEL32_FUNCTION(LoadLibraryA);
    LOCATE_KERNEL32_FUNCTION(FindFirstFileA);
    LOCATE_KERNEL32_FUNCTION(FindNextFileA);
    
    SIZE_T VarSize = GetEnvVarByHash(WINDIR, DirSearchString);
    if (VarSize == 0 || VarSize > MAX_PATH)
        return NULL;
    StringConcatA(DirSearchString, "\\*");

    if ((hFile = FindFirstFileA_(DirSearchString, &FileData)) == INVALID_HANDLE_VALUE) {
        return NULL;
    }
    do 
    {
        if (HashString(FileData.cFileName) == SYSTEM32) 
        {
            DirSearchString[StringLengthA(DirSearchString) - 1] = '\0';
            StringConcatA(DirSearchString, FileData.cFileName);         
            StringConcatA(DirSearchString, "\\*");                      
            System32Found = TRUE;
        }
    } 
    while (FindNextFileA_(hFile, &FileData) != 0 || System32Found != TRUE);

    if (!System32Found)
        return NULL;

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

