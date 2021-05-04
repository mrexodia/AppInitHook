#include "HookDll.hpp"

#include <cstdio>

HOOK(Shell32.dll, HINSTANCE WINAPI, ShellExecuteA)(
	HWND   hwnd,
	LPCSTR lpOperation,
	LPCSTR lpFile,
	LPCSTR lpParameters,
	LPCSTR lpDirectory,
	INT    nShowCmd
	)
{
	dlogp("\"%s\"", lpFile);
	return original_ShellExecuteA(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
}

HOOK_ENTRYPOINT()
{
	dlog();
	auto commandLine = GetCommandLineW();
	if (wcsstr(commandLine, L" --clean"))
	{
		auto FileExists = [](const wchar_t* szFileName)
		{
			return GetFileAttributesW(szFileName) != INVALID_FILE_ATTRIBUTES;
		};
		bool cacheDeleted = true;
		if (FileExists(L"CMakeCache.txt"))
		{
			if (system("del CMakeCache.txt > nul 2>&1") != 0)
			{
				cacheDeleted = false;
				puts("Failed to delete CMakeCache.txt");
			}
		}
		bool filesDeleted = true;
		if (FileExists(L"CMakeFiles"))
		{
			if (system("rmdir /q /s CMakeFiles") != 0)
			{
				filesDeleted = false;
			}
		}
		return filesDeleted && cacheDeleted ? EXIT_SUCCESS : EXIT_FAILURE;
	}
	else if (wcsstr(commandLine, L"--clear"))
	{
		// TODO: nicer error handling
		// Thanks to Jonas for the help with the command
		system("rmdir /s /q . > nul 2>&1 & dir /b");
		return 0;
	}
	return original_EntryPoint();
}

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
)
{
	return HookDllMain(hinstDLL, fdwReason, lpvReserved);
}