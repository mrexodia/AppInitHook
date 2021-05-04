#define MODULENAME "HookDll"
#include "HookDll.hpp"

#include <cstdarg>
#include <cstdio>
#include <iterator>

// Empty export to allow adding this DLL to the IAT
extern "C" __declspec(dllexport) void inject() { }

static char dprintf_msg[66000];

void dprintf(const char* format, ...)
{
	va_list args;
	va_start(args, format);
	*dprintf_msg = 0;
	auto len = vsnprintf_s(dprintf_msg, sizeof(dprintf_msg), format, args);
	for (; len > 1; len--)
	{
		auto& ch = dprintf_msg[len - 1];
		if (ch == '\r' || ch == '\n')
			ch = '\0';
		else
			break;
	}
	OutputDebugStringA(dprintf_msg);
}

void dputs(const char* text)
{
	dprintf("%s\n", text);
}

// Call this from your DllMain to use the HOOK macros
BOOL WINAPI HookDllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		char szModuleName[MAX_PATH] = "";
		GetModuleFileNameA(hinstDLL, szModuleName, _countof(szModuleName));
		auto backslash = strrchr(szModuleName, '\\');
		if (backslash)
		{
			backslash++;
			memmove(szModuleName, backslash, strlen(backslash) + 1);
			auto period = strrchr(szModuleName, '.');
			if (period)
			{
				*period = L'\0';
			}
		}
		auto initStatus = MH_Initialize();
		if (initStatus != MH_OK)
		{
			dprintf("[AppInitHook] [%s] MH_Initialize failed, status: %s",
				szModuleName,
				MH_StatusToString(initStatus)
			);
			return FALSE;
		}
		int hooksInstalled = 0;
		for (auto hook = std::next(&hooks_begin); hook != &hooks_end; ++hook, hooksInstalled++)
		{
			auto hookStatus = MH_CreateHookApi(hook->pszModule, hook->pszProcName, hook->pDetour, hook->ppOriginal);
			if (hookStatus != MH_OK)
			{
				dprintf("[AppInitHook] [%s] Failed to hook %S:%s, status: %s",
					szModuleName,
					hook->pszModule,
					hook->pszProcName,
					MH_StatusToString(hookStatus)
				);
				return FALSE;
			}
			else
			{
				dprintf("[AppInitHook] [%s] Hooked %S:%s",
					szModuleName,
					hook->pszModule,
					hook->pszProcName
				);
			}
		}
		if (hooksInstalled > 0)
		{
			auto enableStatus = MH_EnableHook(MH_ALL_HOOKS);
			if (enableStatus != MH_OK)
			{
				dprintf("[AppInitHook] [%s] MH_EnableHook failed, status: %s",
					szModuleName,
					MH_StatusToString(enableStatus)
				);
				return FALSE;
			}
		}
	}
	return TRUE;
}