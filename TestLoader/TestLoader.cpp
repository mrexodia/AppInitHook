#include <ntdll/ntdll.h>

int main()
{
	HANDLE h;
	NtOpenProcessTokenEx(GetCurrentProcess(), GENERIC_ALL, 0, &h);
	MessageBoxA(0, "Hello world!", "TestLoader", MB_SYSTEMMODAL);
	OutputDebugStringA("[AppInitHook] main()");
}