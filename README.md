# AppInitHook

Global user-mode hooking framework, based on [AppInit_DLLs](https://docs.microsoft.com/en-nz/windows/win32/dlls/secure-boot-and-appinit-dlls). The goal is to allow you to rapidly develop hooks to inject in an arbitrary process.

## Building & Usage

```sh
cmake -B build
cmake --build build --config Release
```

- Customize `Libraries/AppInitDispatcher/install_*.reg` to point to the right DLL path and import it (this will be integrated into the project as a custom target later).
- Copy `AppInitHook.ini` to `build/Release/AppInitHook.ini` and modify it to suit your needs.

## Private Modules

If you enable `-DAPPINITHOOK_PRIVATE_MODULES=ON` it will look for `Private/cmake.toml` where you can add your own modules:

```toml
[target.MyPrivateModule]
type = "shared"
sources = ["MyPrivateModule/*.cpp", "MyPrivateModule/*.h"]
link-libraries = ["HookDll"]
```

## Credits

Template icon: https://www.1001freedownloads.com/free-clipart/syringe-icon
