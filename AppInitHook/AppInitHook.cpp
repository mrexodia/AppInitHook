#include <windows.h>

wchar_t szDispatcherPath[MAX_PATH];

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
	)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		GetModuleFileNameW(hinstDLL, szDispatcherPath, _countof(szDispatcherPath));
		for (int i = lstrlenW(szDispatcherPath) - 1; i > 0 && szDispatcherPath[i] != '\\'; i--)
			szDispatcherPath[i] = L'\0';
		OutputDebugStringA("[AppInitHook] The bomb has been planted!\n");
#ifdef _WIN64
		lstrcatW(szDispatcherPath, L"AppInitDispatcher_x64.dll");
#else
		lstrcatW(szDispatcherPath, L"AppInitDispatcher_x86.dll");
#endif //_WIN64
		LoadLibraryW(szDispatcherPath);
	}
	return FALSE;
}