#include "ntdll/ntdll.h"
#include <Windows.h>
#include "debug.h"
#include "MinHook/MinHook.h"
#include <string>

static decltype(&SetWindowTextW) original_SetWindowTextW;

static BOOL WINAPI hook_SetWindowTextW(
    __in HWND hWnd,
    __in_opt LPCWSTR lpString)
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

template<class Func>
static MH_STATUS WINAPI MH_CreateHookApi(const wchar_t* pszModule, const char* pszProcName, Func* pDetour, Func*& ppOriginal)
{
    return MH_CreateHookApi(pszModule, pszProcName, pDetour, (LPVOID*)&ppOriginal);
}

static bool FileExists(const wchar_t* szFileName)
{
    DWORD attrib = GetFileAttributesW(szFileName);
    return (attrib != INVALID_FILE_ATTRIBUTES && !(attrib & FILE_ATTRIBUTE_DIRECTORY));
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
        if (MH_CreateHookApi(L"user32.dll", "SetWindowTextW", hook_SetWindowTextW, original_SetWindowTextW) != MH_OK)
        {
            dlogp("MH_CreateHook failed");
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