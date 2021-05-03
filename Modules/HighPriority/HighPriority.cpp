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
		auto hProcess = OpenProcess(PROCESS_SET_INFORMATION, FALSE, GetCurrentProcessId());
		if (hProcess)
		{
			SetPriorityClass(hProcess, HIGH_PRIORITY_CLASS);
			CloseHandle(hProcess);
			dlogp("High priority bois!");
		}
	}
	return FALSE;
}