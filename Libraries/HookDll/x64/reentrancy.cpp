#include <HookDll/HookDll.hpp>

unsigned char* MakeReentrantDetour(const Hook* hook, PVOID& pDetour)
{
	// Allocate a TLS index for this process
	static DWORD tlsIndex = TlsAlloc();

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
		return nullptr;
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

	return stub;
}

bool ApplyReentrantHookProtection(const Hook* hook, unsigned char* stub)
{
	// Copy in the original function pointer
	memcpy(stub + 0x46, hook->ppOriginal, sizeof(*hook->ppOriginal));

	// Change to execute-only
	DWORD oldProtect = 0;
	if (!VirtualProtect(stub, 0x1000, PAGE_EXECUTE_READ, &oldProtect))
	{
		dlogp("Failed to protect reentrancy stub for %S:%s, LastError: %d", hook->pszModule, hook->pszProcName, GetLastError());
		return false;
	}
	return true;
}