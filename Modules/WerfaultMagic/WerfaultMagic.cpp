#include "HookDll.hpp"

#include <string>

HOOK(ntdll.dll, NTSTATUS NTAPI, NtQueryValueKey)(
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

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
)
{
	return HookDllMain(hinstDLL, fdwReason, lpvReserved);
}