#include <Windows.h>
#include <stdio.h>
int main()
{
	//MessageBoxA(0, "hello world!", "TestLoader", MB_SYSTEMMODAL);
	auto hLib = LoadLibraryW(L"AppInitHook.dll");
	printf("hLib: %p\n", hLib);
	if (hLib)
		FreeLibrary(hLib);
	OutputDebugStringA("[AppInitHook] main()");
	SetCurrentDirectoryW(L"C:\\AV_disabled");
}