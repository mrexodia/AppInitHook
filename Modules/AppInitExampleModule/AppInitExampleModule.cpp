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
		if (MH_Initialize() != MH_OK)
		{
			dlogp("MH_Initialize failed");
			return FALSE;
		}
		if (MH_CreateHookApi(L"kernelbase.dll", "SetCurrentDirectoryW", hook_SetCurrentDirectoryW, original_SetCurrentDirectoryW) != MH_OK)
		{
			dlogp("MH_CreateHook failed");
			return FALSE;
		}
		if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
		{
			dlogp("MH_EnableHook failed");
			return FALSE;
		}
	}
	return TRUE;
}