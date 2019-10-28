#include "CemuMagic.h"
#include "debug.h"
#include "MinHook/MinHook.h"

extern "C" void __declspec(dllexport) inject() { }

static bool proxyEnabled = false;

static CURLcode hook_Curl_vsetopt(CURL* curl, CURLoption option, va_list arg);
static CURLcode hook_curl_easy_getinfo(CURL *curl, CURLINFO info, void* p);

decltype(&hook_Curl_vsetopt) original_Curl_vsetopt;
decltype(&curl_easy_init) original_curl_easy_init;
decltype(&curl_easy_cleanup) original_curl_easy_cleanup;
decltype(&hook_curl_easy_getinfo) original_curl_easy_getinfo;
decltype(&CreateFileW) original_CreateFileW;

template<class Func>
static MH_STATUS WINAPI MH_CreateHookRva(ULONG_PTR rva, Func* pDetour, Func*& ppOriginal)
{
    auto base = (char*)GetModuleHandleA(NULL);
    return MH_CreateHook(base + rva, pDetour, (LPVOID*)&ppOriginal);
}

template<class Func>
static MH_STATUS WINAPI MH_CreateHookApi(const wchar_t* pszModule, const char* pszProcName, Func* pDetour, Func*& ppOriginal)
{
	return MH_CreateHookApi(pszModule, pszProcName, pDetour, (LPVOID*)&ppOriginal);
}

static ULONG_PTR checkModule()
{
    auto hMod = GetModuleHandleA(NULL);
    if(!hMod)
        return 0;
    auto pdh = (PIMAGE_DOS_HEADER)hMod;
    if(pdh->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;
    auto pnth = (PIMAGE_NT_HEADERS)((char*)hMod + pdh->e_lfanew);
    if(pnth->Signature != IMAGE_NT_SIGNATURE)
        return 0;
    if(pnth->FileHeader.TimeDateStamp != 0x5CFA5F15)
        return 0;
    return ULONG_PTR(hMod);
}

struct CurlHookData
{
    char* pvt = nullptr;
};

static CurlHookData* getHookData(CURL* curl)
{
    CurlHookData* pvt = nullptr;
    original_curl_easy_getinfo(curl, CURLINFO_PRIVATE, &pvt);
    return pvt;
}

static CURLcode original_curl_easy_setopt(CURL* curl, CURLoption option, ...)
{
    va_list arg;
    CURLcode result;

    if(!curl)
        return CURLE_BAD_FUNCTION_ARGUMENT;

    va_start(arg, option);

    result = original_Curl_vsetopt(curl, option, arg);

    va_end(arg);
    return result;
}

static CURLcode hook_Curl_vsetopt(CURL* curl, CURLoption option, va_list param)
{
    va_list arg;
    va_copy(arg, param);
    switch(option)
    {
    case CURLOPT_URL:
    {
        auto url = va_arg(param, char*);
        dlogp("curl: 0x%p, CURLOPT_URL: '%s'", curl, url);
        break;
    }
    case CURLOPT_HTTPHEADER:
    {
        auto headers = va_arg(param, struct curl_slist*);
        auto str = slist2str(headers);
        dlogp("curl: 0x%p, CURLOPT_HTTPHEADER: %s", curl, str.c_str());
        break;
    }
    case CURLOPT_POSTFIELDS:
    {
        auto postdata = va_arg(param, char*);
        if(!postdata)
            postdata = "<nullptr>";
        dlogp("curl: 0x%p, CURLOPT_POSTFIELDS: '%s'", curl, postdata);
        break;
    }
    case CURLOPT_POSTFIELDSIZE:
    {
        auto size = va_arg(param, long);
        dlogp("curl: 0x%p, CURLOPT_POSTFIELDSIZE: %u", curl, size);
        break;
    }
    case CURLOPT_PRIVATE:
    {
        auto pvt = va_arg(param, void*);
        dlogp("curl: 0x%p, CURLOPT_PRIVATE: 0x%p", curl, pvt);
        auto result = original_curl_easy_getinfo(curl, CURLINFO_PRIVATE, pvt);
        if(result == CURLE_OK)
        {
            auto storedpvt = *(CurlHookData**)pvt;
            *(char**)pvt = storedpvt->pvt;
        }
        va_end(param);
        return result;
    }
    case CURLOPT_SSL_VERIFYPEER:
    {
        auto verify = va_arg(param, long);
        dlogp("curl: 0x%p, CURLOPT_SSL_VERIFYPEER: %u", curl, verify);
		if(proxyEnabled)
		{
			auto result = original_curl_easy_setopt(curl, option, 0);
			va_end(param);
			return result;
		}
		break;
    }
    case CURLOPT_SSL_VERIFYHOST:
    {
        auto verify = va_arg(param, long);
        dlogp("curl: 0x%p, CURLOPT_SSL_VERIFYHOST: %u", curl, verify);
		if(proxyEnabled)
		{
			auto result = original_curl_easy_setopt(curl, option, 0);
			va_end(param);
			return result;
		}
		break;
    }
    case CURLOPT_WRITEFUNCTION:
    {
        auto writefunc = va_arg(param, curl_write_callback);
        dlogp("curl: 0x%p, CURLOPT_WRITEFUNCTION: 0x%p", curl, writefunc);
        break;
    }
    case CURLOPT_WRITEDATA:
    {
        auto data = va_arg(param, void*);
        dlogp("curl: 0x%p, CURLOPT_WRITEDATA: 0x%p", curl, data);
        break;
    }
    default:
    {
        dlogp("curl: 0x%p, option: %s, ...", curl, option2str(option));
        break;
    }
    }
    va_end(param);
    return original_Curl_vsetopt(curl, option, arg);
}

static CURL* hook_curl_easy_init()
{
    auto curl = original_curl_easy_init();
    dlogp("0x%p", curl);
    if(curl)
    {
        auto pvt = new CurlHookData();
        if(original_curl_easy_setopt(curl, CURLOPT_PRIVATE, pvt) != CURLE_OK)
            delete pvt;
		if(proxyEnabled)
		{
			auto res = original_curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
			dlogp("CURLOPT_SSL_VERIFYHOST: %d", res);
			res = original_curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
			dlogp("CURLOPT_SSL_VERIFYPEER: %d", res);
			res = original_curl_easy_setopt(curl, CURLOPT_PROXY, "127.0.0.1:8888");
			dlogp("CURLOPT_PROXY: %d", res);
		}
    }
    return curl;
}

static void hook_curl_easy_cleanup(CURL* curl)
{
    dlogp("0x%p", curl);
    CurlHookData* pvt = nullptr;
    if(original_curl_easy_getinfo(curl, CURLINFO_PRIVATE, &pvt) == CURLE_OK)
        delete pvt;
    original_curl_easy_cleanup(curl);
}

static CURLcode hook_curl_easy_getinfo(CURL *curl, CURLINFO info, void* p)
{
    dlogp("curl: 0x%p, info: %s, p: 0x%p", curl, info2str(info), p);
    switch(info)
    {
    case CURLINFO_SSL_VERIFYRESULT:
    {
		if(proxyEnabled)
		{
			// everything is always great
			*(long*)p = 1;
		}
        break;
    }
    case CURLINFO_PRIVATE:
    {
        auto result = original_curl_easy_getinfo(curl, info, p);
        if(result == CURLE_OK)
        {
            auto storedpvt = *(CurlHookData**)p;
            *(char**)p = storedpvt->pvt;
        }
        return result;
    }
    }
    return original_curl_easy_getinfo(curl, info, p);
}

static HANDLE WINAPI hook_CreateFileW(
	__in     LPCWSTR lpFileName,
	__in     DWORD dwDesiredAccess,
	__in     DWORD dwShareMode,
	__in_opt LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	__in     DWORD dwCreationDisposition,
	__in     DWORD dwFlagsAndAttributes,
	__in_opt HANDLE hTemplateFile
)
{
	if(proxyEnabled && lpFileName)
	{
		if(wcsstr(lpFileName, L"\\CACERT_NINTENDO_") || wcsstr(lpFileName, L"/CACERT_NINTENDO_") || wcsstr(lpFileName, L"/seeprom.bin") || wcsstr(lpFileName, L"/otp.bin") || wcsstr(lpFileName, L"account.dat"))
		{
			std::wstring proxyFilename = lpFileName;
			proxyFilename += L".proxy";
			dlogp("%S -> %S", lpFileName, proxyFilename.c_str());
			auto hFile = original_CreateFileW(proxyFilename.c_str(), dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
			if (hFile == INVALID_HANDLE_VALUE)
				dlogp("not found: %S", proxyFilename.c_str());
			return hFile;
		}
	}
	return original_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
	)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
        auto hCemu = checkModule();
        if(!hCemu)
        {
            dlogp("Module doesn't match");
            return FALSE;
        }
		if (MH_Initialize() != MH_OK)
		{
			dlogp("MH_Initialize failed");
			return FALSE;
		}
        if(MH_CreateHookRva(0x3AE5C0, hook_Curl_vsetopt, original_Curl_vsetopt) != MH_OK)
		{
			dlogp("MH_CreateHook failed (Curl_vsetopt)");
			return FALSE;
		}
        if(MH_CreateHookRva(0x3ADF80, hook_curl_easy_init, original_curl_easy_init) != MH_OK)
        {
            dlogp("MH_CreateHook failed (curl_easy_init)");
            return FALSE;
        }
        if(MH_CreateHookRva(0x3ADF40, hook_curl_easy_cleanup, original_curl_easy_cleanup) != MH_OK)
        {
            dlogp("MH_CreateHook failed (curl_easy_cleanup)");
            return FALSE;
        }
        if(MH_CreateHookRva(0x3ADF50, hook_curl_easy_getinfo, original_curl_easy_getinfo) != MH_OK)
        {
            dlogp("MH_CreateHook failed (curl_easy_getinfo)");
            return FALSE;
        }
		if(MH_CreateHookApi(L"kernelbase.dll", "CreateFileW", hook_CreateFileW, original_CreateFileW) != MH_OK)
		{
			dlogp("MH_CreateHook failed (CreateFileW)");
			return FALSE;
		}
		if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
		{
			dlogp("MH_EnableHook failed");
			return FALSE;
		}
		if(GetAsyncKeyState(VK_CONTROL))
		{
			dlogp("Proxy enabled!");
			proxyEnabled = true;
		}
		else
		{
			dlogp("Proxy disabled!");
			proxyEnabled = false;
		}
        dlogp("Done!");
	}
	return TRUE;
}