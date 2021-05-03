#include "ntdll/ntdll.h"
#include <Windows.h>
#include "debug.h"
#include "MinHook/MinHook.h"

decltype(&SetCurrentDirectoryW) original_SetCurrentDirectoryW;

static BOOL WINAPI hook_SetCurrentDirectoryW(__in LPCWSTR lpPathName)
{
	dlogp("'%S'", lpPathName);
	return original_SetCurrentDirectoryW(lpPathName);
}

template<class Func>
static MH_STATUS WINAPI MH_CreateHookApi(const wchar_t* pszModule, const char* pszProcName, Func* pDetour, Func*& ppOriginal)
{
	return MH_CreateHookApi(pszModule, pszProcName, pDetour, (LPVOID*)&ppOriginal);
}

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

		if (MH_Initialize() != MH_OK)
		{
			dlogp("MH_Initialize failed");
			return FALSE;
		}
		if (MH_CreateHookApi(L"kernelbase.dll", "SetCurrentDirectoryW", hook_SetCurrentDirectoryW, original_SetCurrentDirectoryW) != MH_OK)
		{
			dlogp("MH_CreateHook failed");
			return FALSE;
		}
		if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
		{
			dlogp("MH_EnableHook failed");
			return FALSE;
		}
	}
	return TRUE;
}