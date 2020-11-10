#include "ntdll/ntdll.h"
#include <Windows.h>
#include "debug.h"
#include "MinHook/MinHook.h"
#include "vid.h"

extern "C" __declspec(dllexport) void surprise() { }

struct Hook
{
	const wchar_t* pszModule;
	const char* pszProcName;
	PVOID pDetour;
	PVOID* ppOriginal;
};

// Can's magic macro for passing macrofn(ESCAPE(T<int, int>))
#define ESCAPE(...) __VA_ARGS__

#pragma section(".hooks$1",long,read)
#pragma section(".hooks$2",long,read)
#pragma section(".hooks$3",long,read)
#pragma comment(linker, "/merge:hooks=.rdata")

// Can's magic2
__declspec(allocate(".hooks$1")) const Hook hooks_begin;
__declspec(allocate(".hooks$3")) const Hook hooks_end;

// You likely forgot about WINAPI
// error C2373: 'hook_Function': redefinition; different type modifiers
#define HOOK(Dll, ReturnType, Function) \
	static decltype(&Function) original_ ## Function; \
	static decltype(Function) hook_ ## Function; \
	__declspec(allocate(".hooks$2")) const Hook dupa ## Function = { L ### Function, #Function, hook_ ## Function, (LPVOID*)&original_ ## Function }; \
	static ReturnType hook_ ## Function

HOOK(vid.dll, BOOL WINAPI, VidRegisterCpuidHandler)(
	__in PT_HANDLE Partition,
	__in VID_PROCESSOR_INDEX ProcessorIndex,
	__in VID_QUEUE_HANDLE MessageQueue,
	__in UINT32 CpuidFunction,
	__in PVOID UserContext,
	__out HANDLER_REF* HandlerRef
)
{
	dlog();
	return original_VidRegisterCpuidHandler(Partition, ProcessorIndex, MessageQueue, CpuidFunction, UserContext, HandlerRef);
}

#include <iterator>

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
	)
{
	dlog();
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
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