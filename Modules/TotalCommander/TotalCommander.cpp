#include "HookDll.hpp"
#include <string>

HOOK(user32.dll, BOOL WINAPI, SetWindowTextW)(
	__in HWND hWnd,
	__in_opt LPCWSTR lpString
)
{
	if (lpString)
	{
#ifdef _WIN64
		auto totalCommander = L"Total Commander (x64) ";
#else
		auto totalCommander = L"Total Commander ";
#endif //_WIN64
		if (wcsstr(lpString, totalCommander))
		{
			wchar_t szClassName[64] = L"";
			GetClassNameW(hWnd, szClassName, _countof(szClassName));
			if (wcscmp(szClassName, L"TTOTAL_CMD") == 0)
			{
				dlogp("Fixed title!");
				std::wstring newText = lpString;
				auto dashIdx = newText.find(L"Total Commander");
				if (dashIdx != std::wstring::npos)
					newText.resize(dashIdx + 15);
				return original_SetWindowTextW(hWnd, newText.c_str());
			}
		}
	}
	return original_SetWindowTextW(hWnd, lpString);
}

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
)
{
	return HookDllMain(hinstDLL, fdwReason, lpvReserved);
}