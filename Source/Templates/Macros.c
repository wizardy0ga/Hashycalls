# define LOCATE_KERNEL32_FUNCTION(ApiCallName) fp##ApiCallName ApiCallName##_ = (fp##ApiCallName)GetProcAddressByHash(GetModuleHandleByHash(hc_KERNEL32), hc_##ApiCallName##_Hash); \
if (!ApiCallName##_) { return FALSE; }\

# define LOCATE_KERNELBASE_FUNCTION(ApiCallName) fp##ApiCallName ApiCallName##_ = (fp##ApiCallName)GetProcAddressByHash(GetModuleHandleByHash(hc_KERNELBASE), hc_##ApiCallName##_Hash); \
if (!ApiCallName##_) { return FALSE; }\

# define LOCATE_NTDLL_FUNCTION(ApiCallName) fp##ApiCallName ApiCallName##_ = (fp##ApiCallName)GetProcAddressByHash(GetModuleHandleByHash(hc_NTDLL), hc_##ApiCallName##_Hash); \
if (!ApiCallName##_) { return FALSE; }\

/* Temporarily disabled pending future update to base template */
// #define LOCATE_FUNCTION(ApiCallName, ModuleHash) fp##ApiCallName ApiCallName##_ = (fp##ApiCallName)GetProcAddressByHash(GetModuleHandleByHash(ModuleHash), ApiCallName##_Hash); \
// if (!ApiCallName##_) { return FALSE; }\
