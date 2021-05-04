#include "HookDll.hpp"
#include "Utf8Ini.hpp"

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

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		dlog();
		wchar_t szDllPath[MAX_PATH] = L"";
		GetModuleFileNameW(hinstDLL, szDllPath, _countof(szDllPath));
		{
			auto p = wcsrchr(szDllPath, L'\\');
			if (!p)
			{
				dlogp("Failed to get settings path");
				return FALSE;
			}
			*p = L'\0';
		}

		wchar_t szIniPath[MAX_PATH] = L"";
		wcsncpy_s(szIniPath, szDllPath, _TRUNCATE);
		wcsncat_s(szIniPath, L"\\AppInitHook.ini", _TRUNCATE);
		dlogp("Settings: '%S'", szIniPath);

		std::string processName;
		{
			wchar_t szProcessPath[MAX_PATH] = L"";
			GetModuleFileNameW(GetModuleHandleW(nullptr), szProcessPath, _countof(szProcessPath));
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
		auto dllToLoad = Utf8ToUtf16(ini.GetValue(processName, "Module").c_str());
		if (!dllToLoad.empty())
		{
			if (dllToLoad.find_first_of('\\') == std::wstring::npos)
			{
				dllToLoad = szDllPath + (L"\\" + dllToLoad);
			}
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