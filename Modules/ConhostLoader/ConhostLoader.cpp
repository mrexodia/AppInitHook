#include "HookDll.hpp"

static DWORD GetParentPid()
{
	PROCESS_BASIC_INFORMATION pbi = { 0 };
	ULONG size = 0;
	NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), &size);
	return (DWORD)(UINT_PTR)pbi.InheritedFromUniqueProcessId;
}

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
	)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		auto parentPid = GetParentPid();
		dlogp("parent pid: %u", parentPid);
		auto hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, parentPid);
		if (hProcess)
		{
			BOOL wow64 = FALSE;
			IsWow64Process(hProcess, &wow64);
			dlogp("parent hprocess: %u, wow64: %d", (DWORD)(UINT_PTR)hProcess, wow64);
			if (!wow64)
			{
				auto pDllName = VirtualAllocEx(hProcess, nullptr, 0x1000, MEM_COMMIT, PAGE_READWRITE);
				if (pDllName)
				{
					dlogp("pDllName: 0x%p", pDllName);
#ifdef _WIN64
					auto dllName = "AppInitHook_x64.dll";
#else
					auto dllName = "AppInitHook_x86.dll";
#endif //_WIN64
					SIZE_T written = 0;
					if (WriteProcessMemory(hProcess, pDllName, dllName, strlen(dllName), &written))
					{
						dlogp("wrote dll name in parent");
						auto hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryA"), pDllName, 0, nullptr);
						if (hThread)
						{
							dlogp("injected parent");
							CloseHandle(hThread);
						}
						else
							dlogp("failed to create thread in parent");
					}
					else
					{
						dlogp("failed to write memory in parent");
					}
				}
				else
				{
					dlogp("failed to allocate memory in parent");
				}
			}
			else
			{
				dlogp("wow64 parent is not supported");
			}
			CloseHandle(hProcess);
		}
		else
		{
			dlogp("failed to open parent process");
		}
	}
	return FALSE;
}