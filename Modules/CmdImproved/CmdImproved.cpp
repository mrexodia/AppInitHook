#include "ntdll/ntdll.h"
#include <Windows.h>
#include "debug.h"
#include "MinHook/MinHook.h"

static decltype(&SetCurrentDirectoryW) original_SetCurrentDirectoryW;
static decltype(&SetConsoleTitleW) original_SetConsoleTitleW;

static bool titleCommandCalled = false;
static wchar_t overrideTitle[65536];
static wchar_t currentDirectory[65536];

static BOOL WINAPI hook_SetCurrentDirectoryW(__in LPCWSTR lpPathName)
{
	dlogp("'%S' %d", lpPathName, titleCommandCalled);
	if (!titleCommandCalled)
	{
		auto newTitle = wcsrchr(lpPathName, L'\\');
		newTitle = newTitle ? newTitle + 1 : lpPathName;
		wcsncpy_s(overrideTitle, newTitle, _TRUNCATE);
		dlogp("override title '%S'", newTitle);
		original_SetConsoleTitleW(overrideTitle);
	}
	return original_SetCurrentDirectoryW(lpPathName);
}

static BOOL WINAPI hook_SetConsoleTitleW(_In_ LPCWSTR lpConsoleTitle)
{
	dlogp("old title '%S'", lpConsoleTitle);
	if (wcsstr(lpConsoleTitle, L" - title "))
		titleCommandCalled = true;
	if (!titleCommandCalled)
		lpConsoleTitle = overrideTitle;
	dlogp("final title '%S'", lpConsoleTitle);
	return original_SetConsoleTitleW(lpConsoleTitle);
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
			dlogp("MH_CreateHook failed for SetCurrentDirectoryW");
			return FALSE;
		}
		if (MH_CreateHookApi(L"kernelbase.dll", "SetConsoleTitleW", hook_SetConsoleTitleW, original_SetConsoleTitleW) != MH_OK)
		{
			dlogp("MH_CreateHook failed for SetConsoleTitleW");
			return FALSE;
		}
		if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
		{
			dlogp("MH_EnableHook failed");
			return FALSE;
		}
		dlogp("setting initial title");
		if (GetCurrentDirectoryW(_countof(currentDirectory), currentDirectory))
			SetCurrentDirectoryW(currentDirectory);
	}
	return TRUE;
}