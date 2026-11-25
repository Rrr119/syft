# Ten manually verified ELF/PE dependency fixtures

The binaries in `programs/` are real, small binaries produced by `generate.sh`.
They are committed so `go test` does not require gcc or MinGW.

Manual evidence was checked with:

```sh
objdump -p programs/elf_01 | grep NEEDED
x86_64-w64-mingw32-objdump -p programs/pe_07.exe | grep 'DLL Name'
x86_64-w64-mingw32-objdump -p libraries/syft07-1.dll | grep -E 'ProductVersion|FileVersion'
```

The automated assertion is
`TestLibraryDependencyCatalogerTenManuallyVerifiedBinaries`.

| Binary | Import-table evidence | Syft dependency package(s) |
|---|---|---|
| `elf_01` | `libsyft01.so.1`, `libc.so.6` | `libsyft01.so@1.1.0` from the resolved file; `libc.so@6` |
| `elf_02` | `libsyft02.so.1`, `libc.so.6` | `libsyft02.so@1.2.0`; `libc.so@6` |
| `elf_03` | `libsyft03.so.1`, `libc.so.6` | `libsyft03.so@1.3.0`; `libc.so@6` |
| `elf_04` | `libsyft04.so.1`, `libc.so.6` | `libsyft04.so@1.4.0`; `libc.so@6` |
| `elf_05` | `libsyft05.so.1`, `libc.so.6` | `libsyft05.so@1` (library intentionally absent); `libc.so@6` |
| `elf_06` | `libsyft06.so.1`, `libc.so.6` | `libsyft06.so@1.6.0`; `libc.so@6` |
| `pe_07.exe` | `syft07-1.dll`, `KERNEL32.dll`, `msvcrt.dll` | `syft07-1@1.0.7.0` from `VS_VERSIONINFO`; `KERNEL32`; `msvcrt` |
| `pe_08.exe` | `syft08-1.dll`, `KERNEL32.dll`, `msvcrt.dll` | `syft08-1@1.0.8.0`; `KERNEL32`; `msvcrt` |
| `pe_09.exe` | `syft09-1.dll`, `KERNEL32.dll`, `msvcrt.dll` | `syft09-1@1.0.9.0`; `KERNEL32`; `msvcrt` |
| `pe_10.exe` | `syft10-1.dll`, `KERNEL32.dll`, `msvcrt.dll` | `syft10@1` (DLL intentionally absent); `KERNEL32`; `msvcrt` |

The resolved PE rows are produced by the existing PE version-resource logic and
merge with `pe-binary-package-cataloger`; the merge is covered by
`TestLibraryDependencyCatalogerMergesWithPEPackageCataloger`.
