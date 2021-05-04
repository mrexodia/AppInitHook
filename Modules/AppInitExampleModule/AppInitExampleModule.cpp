#include "HookDll.hpp"

HOOK(kernelbase.dll, BOOL WINAPI, SetCurrentDirectoryW)(
	__in LPCWSTR lpPathName
	)
{
	dlogp("'%S'", lpPathName);
	return original_SetCurrentDirectoryW(lpPathName);
}

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
	)
{
	return HookDllMain(hinstDLL, fdwReason, lpvReserved);
}