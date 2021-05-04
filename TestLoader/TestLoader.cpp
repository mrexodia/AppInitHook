#include <Windows.h>

int main()
{
	MessageBoxA(0, "Hello world!", "TestLoader", MB_SYSTEMMODAL);
	OutputDebugStringA("[AppInitHook] main()");
}