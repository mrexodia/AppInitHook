#include "ntdll/ntdll.h"
#include <Windows.h>
#include "debug.h"
#include "MinHook/MinHook.h"

// Can's magic macro for passing macrofn(ESCAPE(T<int, int>))
#define ESCAPE(...) __VA_ARGS__

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

#include <iterator>
#include <vector>

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
)
{
	dlog();
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		int argc = 0;
		auto argv = CommandLineToArgvW(GetCommandLineW(), &argc);
		for (int i = 0; i < argc; i++)
		{
			auto arg = argv[i];
			if (*arg == '@')
			{
				dlogp("kurwa: %S", arg + 1);
				auto hFile = CreateFileW(arg + 1, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
				if (hFile != INVALID_HANDLE_VALUE)
				{
					auto sz = GetFileSize(hFile, nullptr);
					dlogp("size: %u", sz);
					std::vector<wchar_t> s(sz / 2 + 1);
					DWORD read = 0;
					if (ReadFile(hFile, s.data(), s.size() * 2 - 1, &read, nullptr))
					{
						//MessageBoxW(0, s.data(), 0, MB_SYSTEMMODAL);
						dlogp("%S", s.data() + 1);
					}
					CloseHandle(hFile);
				}
			}
		}
		LocalFree(argv);
		if (MH_Initialize() != MH_OK)
		{
			dlogp("MH_Initialize failed");
			return FALSE;
		}
		for (auto hook = std::next(&hooks_begin); hook != &hooks_end; ++hook)
		{
			if (!MH_CreateHookApi(hook->pszModule, hook->pszProcName, hook->pDetour, hook->ppOriginal))
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