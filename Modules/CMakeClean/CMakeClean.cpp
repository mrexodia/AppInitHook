#include "HookDll.hpp"

#include <cstdio>
#include <string>

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

static bool FileExists(const wchar_t* szFileName)
{
	return GetFileAttributesW(szFileName) != INVALID_FILE_ATTRIBUTES;
};

static wchar_t szCurrentDirectory[MAX_PATH * 10];

HOOK_ENTRYPOINT()
{
	dlog();

	bool restoreCurrentDirectory = false;
	GetCurrentDirectoryW(_countof(szCurrentDirectory), szCurrentDirectory);

	auto commandLine = GetCommandLineW();
	int argc = 0;
	auto argv = CommandLineToArgvW(commandLine, &argc);
	if (argv)
	{
		for (int i = 1; i < argc; i++)
		{
			auto arg = argv[i];
			if (wcsstr(arg, L"-B") == arg)
			{
				const wchar_t* buildDir = nullptr;
				if (wcslen(arg) == 2)
				{
					buildDir = argv[i + 1];
				}
				else if (i + 1 < argc)
				{
					buildDir = arg + 2;
				}

				if (buildDir != nullptr)
				{
					dlogp("SetCurrentDirectory: %S", buildDir);
					SetCurrentDirectoryW(buildDir);
					restoreCurrentDirectory = true;
				}
			}
		}
		LocalFree(argv);
	}
	{
		auto buildDir = wcsstr(commandLine, L"-B");
		if (buildDir)
		{
			// Skip -B
			buildDir += 2;
			// Skip spaces
			while (*buildDir == L' ')
				buildDir++;
		}
	}

	if (wcsstr(commandLine, L" --clean"))
	{
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
		if (FileExists(L"CMakeCache.txt"))
		{
			// TODO: nicer error handling
			// Thanks to Jonas for the help with the command
			system("rmdir /s /q . > nul 2>&1 & dir /b");
		}

		if (restoreCurrentDirectory)
		{
			// Remove the --clear flag and continue execution
			std::wstring cleanCommandLine(commandLine);
			auto clearIdx = cleanCommandLine.find(L"--clear");
			auto hasSpace = cleanCommandLine.size() > clearIdx + 7 && cleanCommandLine[clearIdx + 7] == L' ';
			cleanCommandLine = cleanCommandLine.erase(clearIdx, 7 + hasSpace ? 1 : 0);
			dlogp("commandLine: %S", cleanCommandLine.c_str());
			wcscpy(commandLine, cleanCommandLine.c_str());
		}
		else
		{
			// Fini
			return 0;
		}
	}

	if (restoreCurrentDirectory)
	{
		SetCurrentDirectoryW(szCurrentDirectory);
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