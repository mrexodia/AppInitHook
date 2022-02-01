# AppInitHook

Global user-mode hooking framework, based on [AppInit_DLLs](https://docs.microsoft.com/en-nz/windows/win32/dlls/secure-boot-and-appinit-dlls). The goal is to allow you to rapidly develop hooks to inject in an arbitrary process.

## Building & Usage

```sh
cmake -B build -A x64
cmake --build build --config Release
```

Alternatively you can open this folder in a CMake-supported IDE (Visual Studio, CLion, Qt Creator, etc).

The first time you use this framework you need to build and register `AppInitDispatcher.dll` in the `AppInitDLLs` registry key. You can do so by building the `register_AppInitDLLs` target. This will also create `AppInitHook.ini` in your build folder where you can customize which module gets loaded in which process:

```ini
[TestLoader.exe]
Module=ExitProcess.dll
```

Now if you run the `TestLoader` target you should see it exits immediately instead of showing a `Hello world!` message box.

## Debugging

You can use [DebugView](https://docs.microsoft.com/en-us/sysinternals/downloads/debugview) with the filter `[AppInitHook]*` to see the `dlog` and `dlogp` messages, or you can break on DLL load of `AppInitDispatcher.dll` in [x64dbg](https://x64dbg.com).

## Developing modules

The `AppInitExampleModule` hooks [SetCurrentDirectoryW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setcurrentdirectory):

```cpp
#include "HookDll.hpp"

/* MSDN Signature:
BOOL SetCurrentDirectory(
	LPCTSTR lpPathName
);
*/
HOOK(kernelbase.dll, BOOL WINAPI, SetCurrentDirectoryW)(
	LPCWSTR lpPathName
)
{
	dlogp("'%S'", lpPathName);
	return original_SetCurrentDirectoryW(lpPathName);
}

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
)
{
	return HookDllMain(hinstDLL, fdwReason, lpvReserved);
}
```

For more examples you can check the `Modules` folder.

## Private Modules

If you enable `-DAPPINITHOOK_PRIVATE_MODULES=ON` it will look for `Private/cmake.toml` where you can add your own modules:

```toml
[target.MyPrivateModule]
type = "shared"
sources = ["MyPrivateModule/*.cpp", "MyPrivateModule/*.hpp"]
link-libraries = ["HookDll"]
```

You can set up your own private git repository in this folder if you desire, since the folder is fully ignored by the `.gitignore` of this project.

## Credits

- [MinHook](https://github.com/TsudaKageyu/minhook) by [Tsuda Kageyu](https://github.com/TsudaKageyu)
- `ntdll.h` by [Matthijs Lavrijsen](https://github.com/Mattiwatti)
- [Can Bölük](https://blog.can.ac) for helping with the `HOOK` macro
