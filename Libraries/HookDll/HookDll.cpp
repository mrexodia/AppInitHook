#include "HookDll.hpp"

#include <cstdarg>
#include <cstdio>
#include <iterator>

// Empty export to allow adding this DLL to the IAT
extern "C" __declspec(dllexport) void inject() { }

void dprintf(const char* format, ...)
{
	static char dprintf_msg[1024];
	va_list args;
	va_start(args, format);
	*dprintf_msg = 0;
	//int len = 0;
	auto len = vsnprintf_s(dprintf_msg, sizeof(dprintf_msg), format, args);
	for (; len > 1; len--)
	{
		auto& ch = dprintf_msg[len - 1];
		if (ch == '\r' || ch == '\n')
			ch = '\0';
		else
			break;
	}
	//DebugPrint
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

extern "C" NTSYSAPI PVOID RtlFreeSid(PSID Sid);

extern "C" NTSYSAPI NTSTATUS RtlAllocateAndInitializeSid(
	PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
	UCHAR                     SubAuthorityCount,
	ULONG                     SubAuthority0,
	ULONG                     SubAuthority1,
	ULONG                     SubAuthority2,
	ULONG                     SubAuthority3,
	ULONG                     SubAuthority4,
	ULONG                     SubAuthority5,
	ULONG                     SubAuthority6,
	ULONG                     SubAuthority7,
	PSID * Sid
);

extern "C"
NTSYSAPI
NTSTATUS
RtlAddMandatoryAce(
	_Inout_ PACL Acl,
	_In_ ULONG AceRevision,
	_In_ ULONG AceFlags,
	_In_ PSID Sid,
	_In_ UCHAR AceType,
	_In_ ACCESS_MASK AccessMask
);

using _WORD = uint16_t;
using _DWORD = uint32_t;

static HANDLE CreateDBWinMutex()
{
	_ACL* v0; // rbx
	_ACL* v1; // rdi
	HANDLE hMutex; // r14
	ULONG v3; // esi
	ULONG v4; // esi
	ULONG v5; // esi
	_ACL* v6; // rax
	ULONG v7; // esi
	_ACL* v8; // rax
	PSID Sid; // [rsp+68h] [rbp-39h] BYREF
	PSID v11; // [rsp+70h] [rbp-31h] BYREF
	PSID v12; // [rsp+78h] [rbp-29h] BYREF
	PSID v13; // [rsp+80h] [rbp-21h] BYREF
	SECURITY_ATTRIBUTES MutexAttributes; // [rsp+88h] [rbp-19h] BYREF
	SECURITY_DESCRIPTOR SecurityDescriptor; // [rsp+A0h] [rbp-1h] BYREF
	SID_IDENTIFIER_AUTHORITY ntAuthoritySid; // [rsp+C8h] [rbp+27h] BYREF
	SID_IDENTIFIER_AUTHORITY worldAuthoritySid; // [rsp+D0h] [rbp+2Fh] BYREF
	SID_IDENTIFIER_AUTHORITY v18; // [rsp+D8h] [rbp+37h] BYREF

	*(_WORD*)&ntAuthoritySid.Value[4] = 0x500;
	*(_DWORD*)ntAuthoritySid.Value = 0;
	v0 = 0i64;
	v1 = 0i64;
	hMutex = 0i64;
	*(_DWORD*)worldAuthoritySid.Value = 0;
	*(_WORD*)&worldAuthoritySid.Value[4] = 0x100;
	*(_DWORD*)v18.Value = 0;
	*(_WORD*)&v18.Value[4] = 0x1000;
	Sid = 0i64;
	v11 = 0i64;
	v12 = 0i64;
	v13 = 0i64;
	if (RtlAllocateAndInitializeSid(&ntAuthoritySid, 1u, 0x12u, 0, 0, 0, 0, 0, 0, 0, &Sid) >= 0
		&& RtlAllocateAndInitializeSid(&ntAuthoritySid, 2u, 0x20u, 0x220u, 0, 0, 0, 0, 0, 0, &v11) >= 0
		&& RtlAllocateAndInitializeSid(&worldAuthoritySid, 1u, 0, 0, 0, 0, 0, 0, 0, 0, &v12) >= 0
		&& RtlAllocateAndInitializeSid(&v18, 1u, 0x1000u, 0, 0, 0, 0, 0, 0, 0, &v13) >= 0
		&& RtlCreateSecurityDescriptor(&SecurityDescriptor, 1u) >= 0)
	{
		v3 = RtlLengthSid(v12);
		v4 = RtlLengthSid(v11) + v3;
		v5 = RtlLengthSid(Sid) + 32 + v4;
		v6 = (_ACL*)GlobalAlloc(0, v5);
		v0 = v6;
		if (v6)
		{
			if (RtlCreateAcl(v6, v5, ACL_REVISION) >= 0
				&& RtlAddAccessAllowedAce(v0, ACL_REVISION, 0x120001u, v12) >= 0
				&& RtlAddAccessAllowedAce(v0, ACL_REVISION, 0x1F0001u, Sid) >= 0
				&& RtlAddAccessAllowedAce(v0, ACL_REVISION, 0x1F0001u, v11) >= 0
				&& RtlSetDaclSecurityDescriptor(&SecurityDescriptor, 1u, v0, 0) >= 0)
			{
				v7 = RtlLengthSid(v13) + 16;
				v8 = (_ACL*)GlobalAlloc(0, v7);
				v1 = v8;
				if (v8)
				{
					if (RtlCreateAcl(v8, v7, ACL_REVISION) >= 0
						&& RtlAddMandatoryAce(v1, ACL_REVISION, 0, v13, 0x11u, 1u) >= 0
						&& RtlSetSaclSecurityDescriptor(&SecurityDescriptor, 1u, v1, 0) >= 0)
					{
						MutexAttributes.nLength = 24;
						MutexAttributes.lpSecurityDescriptor = &SecurityDescriptor;
						MutexAttributes.bInheritHandle = 0;
						hMutex = CreateMutexExW(&MutexAttributes, L"DBWinMutex", 0, 0x2120001u);
					}
				}
			}
		}
	}
	if (Sid)
		RtlFreeSid(Sid);
	if (v11)
		RtlFreeSid(v11);
	if (v12)
		RtlFreeSid(v12);
	if (v13)
		RtlFreeSid(v13);
	if (v0)
		GlobalFree(v0);
	if (v1)
		GlobalFree(v1);
	return hMutex;
}

static void OutputDebugStringMeme(LPCSTR lpOutputString)
{
	LPCSTR v1; // rdx
	__int64 stringToPrintLength; // rax
	char* pDBWinBuffer; // r15
	HANDLE hDBWinBufferReadyEvent; // r14
	HANDLE hDBWinDataReadyEvent; // rdi
	HANDLE DBWinMutex; // rax
	HANDLE hDBWinBufferMapping; // rax MAPDST
	unsigned __int64 len; // rbx MAPDST
	int tempLen; // eax
	__int64 tempLen1; // r13
	int bufferLen; // eax
	DWORD LastError; // [rsp+40h] [rbp-298h]
	LPCSTR stringToPrint; // [rsp+80h] [rbp-258h] MAPDST
	ULONG_PTR Arguments[2]; // [rsp+88h] [rbp-250h] BYREF
	char temp[512]; // [rsp+A0h] [rbp-238h] BYREF

	static HANDLE hDBWinMutex;
	static BOOL hasDBWinMutex;

	v1 = "";
	if (lpOutputString)
		v1 = lpOutputString;
	stringToPrint = v1;

	hDBWinBufferMapping = 0i64;                   // __except
	pDBWinBuffer = 0i64;
	hDBWinBufferReadyEvent = 0i64;
	hDBWinDataReadyEvent = 0i64;
	LastError = GetLastError();
	if (!hDBWinMutex && !hasDBWinMutex)
	{
		DBWinMutex = CreateDBWinMutex();
		if (DBWinMutex)
		{
			if (_InterlockedCompareExchange64((volatile signed __int64*)&hDBWinMutex, (signed __int64)DBWinMutex, 0i64))
				CloseHandle(DBWinMutex);
		}
		else
		{
			hasDBWinMutex = 1;
		}
	}
	if (hDBWinMutex && (WaitForSingleObjectEx(hDBWinMutex, 10000u, 0) & 0xFFFFFF7F) == 0)
	{
		hDBWinBufferMapping = OpenFileMappingW(2u, 0, L"DBWIN_BUFFER");
		if (hDBWinBufferMapping)
		{
			pDBWinBuffer = (char*)MapViewOfFile(hDBWinBufferMapping, 6u, 0, 0, 0);
			//pDBWinBuffer = (char*)MapViewOfFileExNuma(hDBWinBufferMapping, 6u, 0, 0, 0i64, 0i64, 0xFFFFFFFF);
			if (pDBWinBuffer)
			{
				hDBWinBufferReadyEvent = OpenEventA(0x100000u, 0, "DBWIN_BUFFER_READY");
				if (hDBWinBufferReadyEvent)
					hDBWinDataReadyEvent = OpenEventA(2u, 0, "DBWIN_DATA_READY");
			}
		}
		if (!hDBWinDataReadyEvent)
			ReleaseMutex(hDBWinMutex);
	}
	len = -1i64;
	do
		++len;
	while (stringToPrint[len]);
	while (len)
	{
		if (!hDBWinDataReadyEvent || WaitForSingleObjectEx(hDBWinBufferReadyEvent, 10000u, 0))
		{
			tempLen = 511;
			if (len < 511)
				tempLen = len;
			tempLen1 = tempLen;
			memcpy(temp, stringToPrint, tempLen);
			temp[tempLen1] = 0;
			DbgPrint("%s", temp);
		}
		else
		{
			*(_DWORD*)pDBWinBuffer = GetCurrentProcessId();
			bufferLen = 4091;
			if (len < 4091)
				bufferLen = len;
			tempLen1 = bufferLen;
			memcpy(pDBWinBuffer + 4, stringToPrint, bufferLen);
			pDBWinBuffer[tempLen1 + 4] = 0;
			SetEvent(hDBWinDataReadyEvent);
		}
		stringToPrint += tempLen1;
		len -= tempLen1;
	}
	if (pDBWinBuffer)
		UnmapViewOfFile(pDBWinBuffer);
	if (hDBWinDataReadyEvent)
	{
		ReleaseMutex(hDBWinMutex);
		CloseHandle(hDBWinDataReadyEvent);
	}
	if (hDBWinBufferReadyEvent)
		CloseHandle(hDBWinBufferReadyEvent);
	if (hDBWinBufferMapping)
		CloseHandle(hDBWinBufferMapping);
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
		// There is a weird behavior when calling OutputDebugString from certain functions
		// While unwinding the SRW lock on the RtlpInvertedFunctionTable is already held
		// and it deadlocks.
		// As a workaround: reimplement the __except handler from OutputDebugStringA
		AddVectoredExceptionHandler(1, [](struct _EXCEPTION_POINTERS* ExceptionInfo) -> LONG
		{
			auto er = ExceptionInfo->ExceptionRecord;
			if (er->ExceptionCode == DBG_PRINTEXCEPTION_C && er->NumberParameters == 2)
			{
				auto length = er->ExceptionInformation[0]; // seems to be ignored?
				auto str = (const char*)er->ExceptionInformation[1];
				OutputDebugStringMeme(str);
				return EXCEPTION_CONTINUE_EXECUTION;
			}
			return EXCEPTION_CONTINUE_SEARCH;
		});

		// Super awful hack
		ntpvm_copy = (decltype(NtProtectVirtualMemory)*)VirtualAlloc(0, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		memcpy(ntpvm_copy, GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtProtectVirtualMemory"), 32);
		DWORD oldProtect;
		VirtualProtect(ntpvm_copy, 0x1000, PAGE_EXECUTE, &oldProtect);
		//MH_VirtualProtect = VirtualProtectSyscall;

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