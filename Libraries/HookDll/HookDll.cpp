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

static decltype(NtProtectVirtualMemory)* ntpvm_copy;

static BOOL WINAPI VirtualProtectSyscall(
	_In_  LPVOID lpAddress,
	_In_  SIZE_T dwSize,
	_In_  DWORD flNewProtect,
	_Out_ PDWORD lpflOldProtect)
{
	return NT_SUCCESS(ntpvm_copy(GetCurrentProcess(), &lpAddress, &dwSize, flNewProtect, lpflOldProtect));
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
		// Super awful hack
		ntpvm_copy = (decltype(NtProtectVirtualMemory)*)VirtualAlloc(0, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		memcpy(ntpvm_copy, GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtProtectVirtualMemory"), 32);
		DWORD oldProtect;
		VirtualProtect(ntpvm_copy, 0x1000, PAGE_EXECUTE, &oldProtect);
		MH_VirtualProtect = VirtualProtectSyscall;

#ifdef _WIN64
		auto tlsIndex = TlsAlloc();
#endif // _WIN64

		auto initStatus = MH_Initialize();
		if (initStatus != MH_OK)
		{
			dlogp("MH_Initialize failed, status: %s", MH_StatusToString(initStatus));
			return FALSE;
		}
		int hooksInstalled = 0;
		for (auto hook = std::next(&hooks_begin); hook != &hooks_end; ++hook, hooksInstalled++)
		{
			// Skip uninitialized hooks
			if (hook->pDetour == nullptr || hook->ppOriginal == nullptr)
				continue;

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
				auto pDetour = hook->pDetour;

#ifdef _WIN64
				// This is a 'proper' function, see:
				// - https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention
				// - https://docs.microsoft.com/en-us/cpp/build/prolog-and-epilog
				unsigned char stub_template[]
				{
					// sub rsp,0x28
					0x48, 0x83, 0xEC, 0x28,
					// cmp qword ptr gs:[0x1480],0x0
					0x65, 0x48, 0x83, 0x3C, 0x25, 0x80, 0x14, 0x00, 0x00, 0x00,
					// jz do_detour
					0x74, 0x0A,
					// add rsp,0x28
					0x48, 0x83, 0xC4, 0x28,
					// jmp qword ptr [original]
					0xFF, 0x25, 0x25, 0x00, 0x00, 0x00,
					// do_detour:
					// mov qword ptr gs:[0x1480],0x1
					0x65, 0x48, 0xC7, 0x04, 0x25, 0x80, 0x14, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
					// call qword ptr [detour]
					0xFF, 0x15, 0x1A, 0x00, 0x00, 0x00,
					// mov qword ptr gs:[0x1480],0x0
					0x65, 0x48, 0xC7, 0x04, 0x25, 0x80, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					// add rsp,0x28
					0x48, 0x83, 0xC4, 0x28,
					// ret
					0xC3,
					// original:
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					// detour:
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				};

				auto stub = (unsigned char*)VirtualAlloc(0, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
				if (!stub)
				{
					dlogp("Failed to allocate reentrancy stub for %S:%s, LastError: %d", hook->pszModule, hook->pszProcName, GetLastError());
					return FALSE;
				}

				// Copy template
				memcpy(stub, stub_template, sizeof(stub_template));

				// Copy in TLS indices
				DWORD tlsOffset = 0x1480 + sizeof(ULONG_PTR) * tlsIndex;
				memcpy(stub + 9, &tlsOffset, sizeof(tlsOffset));
				memcpy(stub + 31, &tlsOffset, sizeof(tlsOffset));
				memcpy(stub + 50, &tlsOffset, sizeof(tlsOffset));

				// Copy in the detour function pointer
				memcpy(stub + 71, &hook->pDetour, sizeof(hook->pDetour));
				pDetour = stub;
#endif // _WIN64

				auto hookStatus = MH_CreateHookApi(hook->pszModule, hook->pszProcName, pDetour, hook->ppOriginal);
				if (hookStatus != MH_OK)
				{
					dlogp("Failed to hook %S:%s, status: %s", hook->pszModule, hook->pszProcName, MH_StatusToString(hookStatus));
					return FALSE;
				}
				else
				{
#ifdef _WIN64
					// Copy in the original function pointer
					memcpy(stub + 63, hook->ppOriginal, sizeof(*hook->ppOriginal));

					// Change to execute-only
					VirtualProtect(stub, 0x1000, PAGE_EXECUTE, &oldProtect);
#endif // _WIN64

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