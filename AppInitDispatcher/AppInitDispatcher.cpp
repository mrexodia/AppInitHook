#include <Windows.h>
#define DEBUGNAME "AppInitDispatcher"
#include "debug.h"
#include "Utf8Ini.h"

static std::string Utf16ToUtf8(const wchar_t* wstr)
{
	std::string convertedString;
	if (!wstr || !*wstr)
		return convertedString;
	auto requiredSize = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
	if (requiredSize > 0)
	{
		convertedString.resize(requiredSize - 1);
		if (!WideCharToMultiByte(CP_UTF8, 0, wstr, -1, (char*)convertedString.c_str(), requiredSize, nullptr, nullptr))
			convertedString.clear();
	}
	return convertedString;
}

static std::wstring Utf8ToUtf16(const char* str)
{
	std::wstring convertedString;
	if (!str || !*str)
		return convertedString;
	int requiredSize = MultiByteToWideChar(CP_UTF8, 0, str, -1, nullptr, 0);
	if (requiredSize > 0)
	{
		convertedString.resize(requiredSize - 1);
		if (!MultiByteToWideChar(CP_UTF8, 0, str, -1, (wchar_t*)convertedString.c_str(), requiredSize))
			convertedString.clear();
	}
	return convertedString;
}

static DWORD getModuleTimeDateStamp(HMODULE hMod)
{
	DWORD TimeDateStamp = 0;
	__try
	{
		if(!hMod)
			return 0;
		auto pdh = (PIMAGE_DOS_HEADER)hMod;
		if(pdh->e_magic != IMAGE_DOS_SIGNATURE)
			return 0;
		auto pnth = (PIMAGE_NT_HEADERS)((char*)hMod + pdh->e_lfanew);
		if(pnth->Signature != IMAGE_NT_SIGNATURE)
			return 0;
		TimeDateStamp = pnth->FileHeader.TimeDateStamp;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}
	return TimeDateStamp;
}

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
	)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		dlog();
		wchar_t szIniPath[MAX_PATH] = L"";
		GetModuleFileNameW(hinstDLL, szIniPath, _countof(szIniPath));
		{
			auto p = wcsrchr(szIniPath, L'\\');
			if (!p)
			{
				dlogp("Failed to get settings path");
				return FALSE;
			}
			*p = L'\0';
		}
#ifdef _WIN64
		wcsncat_s(szIniPath, L"\\AppInitHook_x64.ini", _TRUNCATE);
#else
		wcsncat_s(szIniPath, L"\\AppInitHook_x86.ini", _TRUNCATE);
#endif //_WIN64
		dlogp("Settings: '%S'", szIniPath);

		auto hMod = GetModuleHandleW(nullptr);

		std::string processName;
		{
			wchar_t szProcessPath[MAX_PATH] = L"";
			GetModuleFileNameW(hMod, szProcessPath, _countof(szProcessPath));
			auto p = wcsrchr(szProcessPath, L'\\');
			if (!p)
			{
				dlogp("Failed to get process path");
				return FALSE;
			}
			processName = Utf16ToUtf8(p + 1);
			for (auto& ch : processName)
				ch = tolower(ch);
		}
		dlogp("Process: '%s'", processName.c_str());

		Utf8Ini ini;
		auto hFile = CreateFileW(szIniPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
		if (hFile != INVALID_HANDLE_VALUE)
		{
			std::string data;
			data.resize(GetFileSize(hFile, nullptr));
			DWORD read = 0;
			if (ReadFile(hFile, (void*)data.data(), (DWORD)data.size(), &read, nullptr))
			{
				int errorLine = 0;
				if (!ini.Deserialize(data, errorLine))
				{
					dlogp("Utf8Ini::Deserialize failed");
					ini.Clear();
				}
				else
				{
					dlogp("Settings deserialized");
				}

			}
			else
			{
				dlogp("Failed to read settings");
			}
			CloseHandle(hFile);
		}
		else
		{
			dlogp("Failed to open settings");
		}
		auto dllToLoadUtf8 = ini.GetValue(processName, "Module");
		if(dllToLoadUtf8.empty())
		{
			DWORD TimeDateStamp = getModuleTimeDateStamp(hMod);
			char timeDateStampText[16] = "";
			sprintf_s(timeDateStampText, "%08X", TimeDateStamp);
			dllToLoadUtf8 = ini.GetValue(processName + ":" + timeDateStampText, "Module");
			if(!dllToLoadUtf8.empty())
				dlogp("Found module with DateTimeStamp %s", timeDateStampText);
		}
		auto dllToLoad = Utf8ToUtf16(dllToLoadUtf8.c_str());
		if (!dllToLoad.empty())
		{
			dlogp("dllToLoad: '%S'", dllToLoad.c_str());
			if (LoadLibraryW(dllToLoad.c_str()))
			{
				dlogp("Successfully loaded module");
			}
			else
			{
				dlogp("Failed to load module");
			}
		}
		else
		{
			dlogp("No module to load for this process");
		}
	}
	return FALSE;
}