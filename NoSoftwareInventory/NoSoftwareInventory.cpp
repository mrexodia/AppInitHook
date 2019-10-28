#include <Windows.h>
#include <stdio.h>

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
)
{
	if(fdwReason == DLL_PROCESS_ATTACH)
	{
		if(wcsstr(GetCommandLineW(), L"aeinv.dll,UpdateSoftwareInventory"))
		{
			OutputDebugStringA("[AppInitHook] [NoSoftwareInventory] ExitProcess(-1)");
			ExitProcess(-1);
		}
	}
	return TRUE;
}