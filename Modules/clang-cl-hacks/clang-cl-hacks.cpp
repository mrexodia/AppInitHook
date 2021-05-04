#include "HookDll.hpp"

#include <iterator>
#include <vector>

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
)
{
	dlog();
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		int argc = 0;
		auto argv = CommandLineToArgvW(GetCommandLineW(), &argc);
		for (int i = 0; i < argc; i++)
		{
			auto arg = argv[i];
			if (*arg == '@')
			{
				dlogp("kurwa: %S", arg + 1);
				auto hFile = CreateFileW(arg + 1, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
				if (hFile != INVALID_HANDLE_VALUE)
				{
					auto sz = GetFileSize(hFile, nullptr);
					dlogp("size: %u", sz);
					std::vector<wchar_t> s(sz / 2 + 1);
					DWORD read = 0;
					if (ReadFile(hFile, s.data(), s.size() * 2 - 1, &read, nullptr))
					{
						//MessageBoxW(0, s.data(), 0, MB_SYSTEMMODAL);
						dlogp("%S", s.data() + 1);
					}
					CloseHandle(hFile);
				}
			}
		}
		LocalFree(argv);
	}
	return HookDllMain(hinstDLL, fdwReason, lpvReserved);
}