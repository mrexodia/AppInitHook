#include "HookDll.hpp"

static bool titleCommandCalled = false;
static wchar_t overrideTitle[65536];
static wchar_t currentDirectory[65536];

HOOK(kernelbase.dll, BOOL WINAPI, SetCurrentDirectoryW)(__in LPCWSTR lpPathName)
{
	dlogp("'%S' %d", lpPathName, titleCommandCalled);
	if (!titleCommandCalled)
	{
		auto newTitle = wcsrchr(lpPathName, L'\\');
		newTitle = newTitle ? newTitle + 1 : lpPathName;
		wcsncpy_s(overrideTitle, newTitle, _TRUNCATE);
		dlogp("override title '%S'", newTitle);
		SetConsoleTitleW(overrideTitle);
	}
	return original_SetCurrentDirectoryW(lpPathName);
}

HOOK(kernelbase.dll, BOOL WINAPI, SetConsoleTitleW)(_In_ LPCWSTR lpConsoleTitle)
{
	dlogp("old title '%S'", lpConsoleTitle);
	if (wcsstr(lpConsoleTitle, L" - title "))
		titleCommandCalled = true;
	if (!titleCommandCalled)
		lpConsoleTitle = overrideTitle;
	dlogp("final title '%S'", lpConsoleTitle);
	return original_SetConsoleTitleW(lpConsoleTitle);
}

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		dlogp("setting initial title");
		if (GetCurrentDirectoryW(_countof(currentDirectory), currentDirectory))
			SetCurrentDirectoryW(currentDirectory);
	}
	return HookDllMain(hinstDLL, fdwReason, lpvReserved);
}