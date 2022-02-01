#pragma once

#include "ntdll/ntdll.h"
#include "MinHook/MinHook.h"

void dprintf(const char* format, ...);
void dputs(const char* text);
const char* modname();

// Call this from your DllMain to use the HOOK macros
BOOL WINAPI HookDllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
);

struct Hook
{
	const wchar_t* pszModule;
	const char* pszProcName;
	PVOID pDetour;
	PVOID* ppOriginal;
};

#ifdef _WIN64
unsigned char* MakeReentrantDetour(const Hook* hook, PVOID& pDetour);
bool ApplyReentrantHookProtection(const Hook* hook, unsigned char* stub);
#else
// TODO: implement for 32 bit
inline unsigned char* MakeReentrantDetour(const Hook* hook, PVOID& pDetour) { return (unsigned char*)1; }
inline bool ApplyReentrantHookProtection(const Hook* hook, unsigned char* stub) { return true; }
#endif // _WIN64

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
	extern "C" __declspec(allocate(".hooks$2")) Hook hookdata_ ## Function = { L ### Dll, #Function, hook_ ## Function, (LPVOID*)&original_ ## Function }; \
	static ReturnType hook_ ## Function

#define HOOK_ENTRYPOINT() \
	int EntryPoint(); \
	static decltype(&EntryPoint) original_EntryPoint; \
	static decltype(EntryPoint) hook_EntryPoint; \
	extern "C" __declspec(allocate(".hooks$2")) Hook hookdata_EntryPoint = { nullptr, nullptr, hook_ ## EntryPoint, (LPVOID*)&original_ ## EntryPoint }; \
	static int hook_EntryPoint()

template<class Func>
static MH_STATUS WINAPI MH_CreateHookApi(const wchar_t* pszModule, const char* pszProcName, Func* pDetour, Func*& ppOriginal)
{
	return MH_CreateHookApi(pszModule, pszProcName, pDetour, (LPVOID*)&ppOriginal);
}

#define dlog() dprintf("[AppInitHook] [%s] [%u] " __FUNCTION__ "\n", modname(), GetCurrentProcessId())
#define dlogp(fmt, ...) dprintf("[AppInitHook] [%s] [%u] " __FUNCTION__ "(" fmt ")\n", modname(), GetCurrentProcessId(), __VA_ARGS__)