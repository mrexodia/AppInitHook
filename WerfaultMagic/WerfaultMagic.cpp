#include "ntdll/ntdll.h"
#include <Windows.h>
#include "debug.h"
#include <string>
#include "MinHook/MinHook.h"

static decltype(&NtQueryValueKey) original_NtQueryValueKey;

static std::wstring safeUnicodeString(PUNICODE_STRING Str)
{
	std::wstring result;
	if (Str && Str->Buffer)
	{
		result.resize(Str->Length / 2);
		for (size_t i = 0; i < result.length(); i++)
			result[i] = Str->Buffer[i];
	}
	return result;
}

static NTSTATUS NTAPI hook_NtQueryValueKey(
	_In_ HANDLE KeyHandle,
	_In_ PUNICODE_STRING ValueName,
	_In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	_Out_ PVOID KeyValueInformation,
	_In_ ULONG Length,
	_Out_ PULONG ResultLength
	)
{
	auto safeValueName = safeUnicodeString(ValueName);
	if (safeValueName == L"Debugger")
	{
		UNICODE_STRING ValueNameMagic;
		ValueNameMagic.Buffer = L"DebuggerMagic";
		ValueNameMagic.Length = (USHORT)wcslen(ValueNameMagic.Buffer) * 2;
		ValueNameMagic.MaximumLength = ValueNameMagic.Length + 2;
		auto magicStatus = original_NtQueryValueKey(KeyHandle, &ValueNameMagic, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
		if (NT_SUCCESS(magicStatus))
			return magicStatus;
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