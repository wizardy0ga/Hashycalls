#define GET_FUNCTION_CALL(FunctionName) fp##FunctionName FunctionName##_ = (fp##FunctionName)(&HashedAPI)->##FunctionName.Address

typedef struct _API_CALL {
    DWORD Hash;
    PVOID Address;
    DWORD ModuleHash;
    HMODULE hModule;
} API_CALL, * PAPI_CALL;
