#include <Windows.h>

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
)
{
	OutputDebugStringA("[AppInitHook] [ForceQuit] ExitProcess(-1)");
	ExitProcess(-1);
	return TRUE;
}