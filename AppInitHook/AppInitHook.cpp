#include <windows.h>

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
	)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		OutputDebugStringA("[AppInitHook] The bomb has been planted!");
		LoadLibraryW(L"AppInitDispatcher.dll");
	}
	return FALSE;
}