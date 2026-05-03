# Build from source

This guide is for contributors who want to compile NetSentinel11 themselves from a clean GitHub checkout.

## Requirements

- Windows 11.
- Visual Studio 2022 or Build Tools for Visual Studio 2022 with the C++ desktop workload.
- CMake 3.24 or newer.
- Qt 6 for the native GUI build.
- PowerShell 7 is recommended for packaging scripts, but Windows PowerShell works for basic build commands.

## Minimal CLI build

This builds the command-line app and backend libraries. It does not require Qt.

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 -DBUILD_TESTING=OFF
cmake --build build --config Release
.\build\bin\Release\netsentinel11.exe --smoke
```

## Full Qt GUI build

Install Qt 6 with the MSVC 2022 64-bit kit, then point CMake at it:

```powershell
$env:CMAKE_PREFIX_PATH = "C:\Qt\6.8.3\msvc2022_64"
cmake -S . -B build-qt -G "Visual Studio 17 2022" -A x64 -DBUILD_TESTING=OFF
cmake --build build-qt --config Release
.\build-qt\bin\Release\netsentinel11_gui.exe
```

If Qt is not found, the backend and CLI still build, but the native GUI executable is skipped.

## Maintainer test build

The public release branch may not include the private/local smoke test folder. If `tests/` is present, maintainers can enable tests:

```powershell
cmake -S . -B build-qt-msvc -G "Visual Studio 17 2022" -A x64 -DBUILD_TESTING=ON -DNETSENTINEL_BUILD_TESTS=ON
cmake --build build-qt-msvc --config Release
ctest --test-dir build-qt-msvc --output-on-failure -C Release
```

## Safe local validation

Use private RFC1918 ranges only and only with permission:

```powershell
.\build-qt\bin\Release\netsentinel11.exe gui action --id scan.trigger --target 192.168.1.0/24 --apply --confirm
```

Do not scan public IP ranges with this tool.
