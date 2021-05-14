#include "HookDll.hpp"

#include <cstdarg>
#include <cstdio>
#include <iterator>

// Empty export to allow adding this DLL to the IAT
extern "C" __declspec(dllexport) void inject() { }

void dprintf(const char* format, ...)
{
	static char dprintf_msg[66000];
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

extern "C" IMAGE_DOS_HEADER __ImageBase;

const char* modname()
{
	static char szModuleName[MAX_PATH];
	if (*szModuleName == '\0')
	{
		GetModuleFileNameA((HMODULE)&__ImageBase, szModuleName, _countof(szModuleName));
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
	}
	return szModuleName;
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
		auto initStatus = MH_Initialize();
		if (initStatus != MH_OK)
		{
			dlogp("MH_Initialize failed, status: %s", MH_StatusToString(initStatus));
			return FALSE;
		}
		int hooksInstalled = 0;
		for (auto hook = std::next(&hooks_begin); hook != &hooks_end; ++hook, hooksInstalled++)
		{
			if (hook->pszModule == nullptr && hook->pszProcName == nullptr)
			{
				void* entryPoint = nullptr;
				auto base = (char*)GetModuleHandleW(nullptr);
				auto pdh = PIMAGE_DOS_HEADER(base);
				if (pdh->e_magic == IMAGE_DOS_SIGNATURE)
				{
					auto pnth = PIMAGE_NT_HEADERS(base + pdh->e_lfanew);
					if (pnth->Signature == IMAGE_NT_SIGNATURE)
					{
						if (pnth->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC)
						{
							entryPoint = base + pnth->OptionalHeader.AddressOfEntryPoint;
						}
					}

				}
				if (entryPoint == nullptr)
				{
					dlogp("Failed to get entry point");
					return FALSE;
				}
				auto hookStatus = MH_CreateHook(entryPoint, hook->pDetour, hook->ppOriginal);
				if (hookStatus != MH_OK)
				{
					dlogp("Failed to hook EntryPoint 0x%p, status: %s", entryPoint, MH_StatusToString(hookStatus));
					return FALSE;
				}
				else
				{
					dlogp("Hooked EntryPoint 0x%p", entryPoint);
				}
			}
			else
			{
				auto hookStatus = MH_CreateHookApi(hook->pszModule, hook->pszProcName, hook->pDetour, hook->ppOriginal);
				if (hookStatus != MH_OK)
				{
					dlogp("Failed to hook %S:%s, status: %s", hook->pszModule, hook->pszProcName, MH_StatusToString(hookStatus));
					return FALSE;
				}
				else
				{
					dlogp("Hooked %S:%s", hook->pszModule, hook->pszProcName);
				}
			}
		}
		if (hooksInstalled > 0)
		{
			auto enableStatus = MH_EnableHook(MH_ALL_HOOKS);
			if (enableStatus != MH_OK)
			{
				dlogp("MH_EnableHook failed, status: %s", MH_StatusToString(enableStatus));
				return FALSE;
			}
		}
	}
	return TRUE;
}