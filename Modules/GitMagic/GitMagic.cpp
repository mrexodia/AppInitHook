#include "HookDll.hpp"

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
	)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		char currentDir[MAX_PATH] = "";
		GetCurrentDirectoryA(_countof(currentDir), currentDir);
		dlogp("currentDir: '%s'", currentDir);
		auto commandLine = GetCommandLineA();
		dlogp("commandLine: '%s'", commandLine);
		if (false && strstr(commandLine, "submodule sync --recursive") && strstr(commandLine, "git.exe"))
			//if (strstr(commandLine, "\"fetch\"") && strstr(commandLine, "git.exe"))
		{
			dlogp("FETCH! Sleeping 20 seconds...");
			char lockfile[MAX_PATH] = "";
			strcpy_s(lockfile, currentDir);
			strcat_s(lockfile, "\\.git\\index.lock");
			auto hFile = CreateFileA(lockfile, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
			dlogp("hFile: %p", hFile);
			if (hFile != INVALID_HANDLE_VALUE)
				CloseHandle(hFile);
			Sleep(20000);
			DeleteFileA(lockfile);
			dlogp("done waiting");
		}
	}
	return TRUE;
}