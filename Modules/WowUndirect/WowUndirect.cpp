#include "ntdll/ntdll.h"
#include <Windows.h>
#include "debug.h"
#include "MinHook/MinHook.h"

extern "C" __declspec(dllexport) void inject() { }

decltype(&SetCurrentDirectoryW) original_SetCurrentDirectoryW;

static BOOL WINAPI hook_SetCurrentDirectoryW(__in LPCWSTR lpPathName)
{
	dlogp("'%S'", lpPathName);
	return original_SetCurrentDirectoryW(lpPathName);
}

template<class Func>
static MH_STATUS WINAPI MH_CreateHookApi(const wchar_t* pszModule, const char* pszProcName, Func* pDetour, Func*& ppOriginal)
{
	return MH_CreateHookApi(pszModule, pszProcName, pDetour, (LPVOID*)&ppOriginal);
}

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
	)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		PVOID oldValue = NULL;
		Wow64DisableWow64FsRedirection(&oldValue);
		dlogp("Disabled redirects");
	}
	return TRUE;
}