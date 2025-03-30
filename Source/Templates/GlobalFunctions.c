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
