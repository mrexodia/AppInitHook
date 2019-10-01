#include "ntdll/ntdll.h"
#include <Windows.h>
#include "debug.h"
#include <string>
#include "MinHook/MinHook.h"

static decltype(&NtQueryValueKey) original_NtQueryValueKey;

static NTSTATUS NTAPI hook_NtQueryValueKey(
	_In_ HANDLE KeyHandle,
	_In_ PUNICODE_STRING ValueName,
	_In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	_Out_ PVOID KeyValueInformation,
	_In_ ULONG Length,
	_Out_ PULONG ResultLength
	)
{
	__try
	{
		UNICODE_STRING DebuggerStr;
		RtlInitUnicodeString(&DebuggerStr, L"Debugger");
		if (RtlCompareUnicodeString(&DebuggerStr, ValueName, TRUE) == 0)
		{
			UNICODE_STRING ValueNameMagic;
			RtlInitUnicodeString(&ValueNameMagic, L"DebuggerMagic");
			auto magicStatus = original_NtQueryValueKey(KeyHandle, &ValueNameMagic, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
			if (NT_SUCCESS(magicStatus))
				return magicStatus;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
	return original_NtQueryValueKey(KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
}

template<class Func>
static MH_STATUS WINAPI MH_CreateHookApi(const wchar_t* pszModule, const char* pszProcName, Func* pDetour, Func*& ppOriginal)
{
	return MH_CreateHookApi(pszModule, pszProcName, pDetour, (LPVOID*)&ppOriginal);
}

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
	)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		if (MH_Initialize() != MH_OK)
		{
			dlogp("MH_Initialize failed");
			return FALSE;
		}
		if (MH_CreateHookApi(L"ntdll.dll", "NtQueryValueKey", hook_NtQueryValueKey, original_NtQueryValueKey) != MH_OK)
		{
			dlogp("MH_CreateHook failed for NtQueryValueKey");
			return FALSE;
		}
		if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
		{
			dlogp("MH_EnableHook failed");
			return FALSE;
		}
	}
	return TRUE;
}