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

				/*
				<$myprivatemodule.1100>
				cmp qword ptr gs:[0x1490], 0x0
				je short @wrap
				jmp qword ptr [@original]
				@wrap:
				push rax
				mov rax, qword ptr [rsp]
				mov qword ptr gs:[0x1490], rax
				lea rax, qword ptr [@unwrap]
				mov qword ptr [rsp+8],rax
				pop rax
				jmp qword ptr [@hook]

				@unwrap:
				push rax
				xor rax, rax
				xchg rax, qword ptr gs:[0x1490]
				xchg rax, qword ptr [rsp]
				ret

				@original:
				dq 0x7FFCCAD80F80
				@hook:
				dq 0x7FFC469C10F0
				*/
				unsigned char stub_template[]
				{
					0x65, 0x48, 0x83, 0x3C, 0x25, 0x90, 0x14, 0x00, 0x00, 0x00,
					0x74, 0x06, 0xFF, 0x25, 0x34, 0x00, 0x00, 0x00, 0x50, 0x48,
					0x8B, 0x44, 0x24, 0x08, 0x65, 0x48, 0x89, 0x04, 0x25, 0x90,
					0x14, 0x00, 0x00, 0x48, 0x8D, 0x05, 0x0C, 0x00, 0x00, 0x00,
					0x48, 0x89, 0x44, 0x24, 0x08, 0x58, 0xFF, 0x25, 0x1A, 0x00,
					0x00, 0x00, 0x50, 0x48, 0x31, 0xC0, 0x65, 0x48, 0x87, 0x04,
					0x25, 0x90, 0x14, 0x00, 0x00, 0x48, 0x87, 0x04, 0x24, 0xC3,
					0x80, 0x0F, 0xD8, 0xCA, 0xFC, 0x7F, 0x00, 0x00, 0xF0, 0x10,
					0x9C, 0x46, 0xFC, 0x7F, 0x00, 0x00
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
				memcpy(stub + 5, &tlsOffset, sizeof(tlsOffset));
				memcpy(stub + 0x18 + 5, &tlsOffset, sizeof(tlsOffset));
				memcpy(stub + 0x38 + 5, &tlsOffset, sizeof(tlsOffset));

				// Copy in the detour function pointer
				memcpy(stub + 0x4e, &hook->pDetour, sizeof(hook->pDetour));
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
					memcpy(stub + 0x46, hook->ppOriginal, sizeof(*hook->ppOriginal));

					// Change to execute-only
					VirtualProtect(stub, 0x1000, PAGE_EXECUTE_READ, &oldProtect);
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