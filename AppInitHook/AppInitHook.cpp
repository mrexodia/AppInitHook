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
#ifdef _WIN64
		LoadLibraryW(L"AppInitDispatcher_x64.dll");
#else
		LoadLibraryW(L"AppInitDispatcher_x86.dll");
#endif //_WIN64
	}
	return FALSE;
}