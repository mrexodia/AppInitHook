#include <Windows.h>
#include "debug.h"

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
	)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		dlogp("Fuck this shit, I'm out of here!");
		ExitProcess(0);
	}
	return TRUE;
}