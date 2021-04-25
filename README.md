# AppInitHook

Global user-mode hooking framework, based on [AppInit_DLLs](https://docs.microsoft.com/en-nz/windows/win32/dlls/secure-boot-and-appinit-dlls). The goal is to allow you to rapidly inject your code in a random process.

## Installation

1. Compile `AppInitHook.sln` (**no binaries will be made available for security reasons!**), for both `Win32` and `x64`.
3. Modify `appinit_x86.reg` and `appinit_x64.reg` to point to the right locations and add them to your registry.
4. Copy `AppInitHook_x86.ini` to `Release` and copy `AppInitHook_x64.ini` to `x64\Release`.

You can now modify the INI files and specify which DLL to load in which process. You can also import `AppInitExampleModuleTemplate.zip` in Visual Studio to rapidly develop new modules.

## Credits

Template icon: https://www.1001freedownloads.com/free-clipart/syringe-icon