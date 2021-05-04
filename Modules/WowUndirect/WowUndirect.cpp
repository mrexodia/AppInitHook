#include "HookDll.hpp"

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