#include "ntdll/ntdll.h"
#include <Windows.h>
#include "debug.h"
#include "MinHook/MinHook.h"

extern "C" __declspec(dllexport) void surprise() { }

struct Hook
{
	const wchar_t* pszModule;
	const char* pszProcName;
	PVOID pDetour;
	PVOID* ppOriginal;
};

#pragma section(".hooks$1",long,read)
#pragma section(".hooks$2",long,read)
#pragma section(".hooks$3",long,read)
#pragma comment(linker, "/merge:hooks=.rdata")

// Can's magic
__declspec(allocate(".hooks$1")) const Hook hooks_begin;
__declspec(allocate(".hooks$3")) const Hook hooks_end;

// You likely forgot about WINAPI
// error C2373: 'hook_Function': redefinition; different type modifiers
#define HOOK(Dll, ReturnType, Function) \
	static decltype(&Function) original_ ## Function; \
	static decltype(Function) hook_ ## Function; \
	extern "C" __declspec(dllexport) __declspec(allocate(".hooks$2")) Hook dupa_ ## Function = { L ### Function, #Function, hook_ ## Function, (LPVOID*)&original_ ## Function }; \
	static ReturnType hook_ ## Function

#define HOOK_ENTRYPOINT() \
	int EntryPoint(); \
	static decltype(&EntryPoint) original_EntryPoint; \
	static decltype(EntryPoint) hook_EntryPoint; \
	extern "C" __declspec(dllexport) __declspec(allocate(".hooks$2")) Hook dupa_EntryPoint = { nullptr, nullptr, hook_ ## EntryPoint, (LPVOID*)&original_ ## EntryPoint }; \
	static int hook_EntryPoint()

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

#include <iterator>

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
)
{
	dlogp("%u", fdwReason);
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		if (MH_Initialize() != MH_OK)
		{
			dlogp("MH_Initialize failed");
			return FALSE;
		}
		for (auto hook = std::next(&hooks_begin); hook != &hooks_end; ++hook)
		{
			if (hook->pszModule == nullptr && hook->pszProcName == nullptr) // EntryPoint hook
			{
				unsigned int entryPointRva = 0;
				auto mod = (char*)GetModuleHandleW(nullptr);
				auto pnth = (PIMAGE_NT_HEADERS)(mod + ((PIMAGE_DOS_HEADER)mod)->e_lfanew);
				auto EntryPoint = mod + pnth->OptionalHeader.AddressOfEntryPoint;
				if (MH_CreateHook(EntryPoint, hook_EntryPoint, (LPVOID*)&original_EntryPoint) != MH_OK)
				{
					dlogp("MH_CreateHookRva failed");
					return FALSE;
				}
			}
			else if (!MH_CreateHookApi(hook->pszModule, hook->pszProcName, hook->pDetour, hook->ppOriginal))
			{
				dlogp("MH_CreateHook(%s) failed", hook->pszProcName);
				return FALSE;
			}
		}
		if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
		{
			dlogp("MH_EnableHook failed");
			return FALSE;
		}
	}
	return TRUE;
}