#!/usr/bin/env bash
set -euo pipefail

# This script rebuilds the ten real ELF/PE fixtures used by
# library_dependency_cataloger_test.go. The compiled files are committed so
# normal `go test` runs do not require gcc or a MinGW cross toolchain.

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
src="$root/src"
programs="$root/programs"
libraries="$root/libraries"

elf_cc="${ELF_CC:-gcc}"
pe_cc="${PE_CC:-x86_64-w64-mingw32-gcc}"
pe_windres="${PE_WINDRES:-x86_64-w64-mingw32-windres}"

rm -rf "$src" "$programs" "$libraries"
mkdir -p "$src" "$programs" "$libraries"

for n in 01 02 03 04 05 06; do
  upper=$((10#$n))
  cat >"$src/libsyft${n}.c" <<EOF
const char *syft_${n}_identity(void) {
    return "syft-${n}-${upper}.0.0";
}
EOF

  cat >"$src/elf_${n}.c" <<EOF
extern const char *syft_${n}_identity(void);
int main(void) {
    return syft_${n}_identity()[0] == 's' ? 0 : 1;
}
EOF

  "$elf_cc" -O2 -fPIC -shared \
    -Wl,-soname,"libsyft${n}.so.1" \
    -o "$libraries/libsyft${n}.so.1.${upper}.0" \
    "$src/libsyft${n}.c"
  ln -sf "libsyft${n}.so.1.${upper}.0" "$libraries/libsyft${n}.so.1"

  "$elf_cc" -O2 \
    -o "$programs/elf_${n}" \
    "$src/elf_${n}.c" \
    -L"$libraries" -l:"libsyft${n}.so.1" \
    -Wl,-rpath,'$ORIGIN/../libraries'
done

# Case 05 deliberately has its dependency absent from the scanned root. The
# DT_NEEDED entry itself is still enough to identify the library reference.
rm -f "$libraries/libsyft05.so"*

for n in 07 08 09 10; do
  upper=$((10#$n))
  cat >"$src/syft${n}.c" <<EOF
__declspec(dllexport) const char *syft_${n}_identity(void) {
    return "syft-${n}-1.0.${upper}";
}
EOF

  cat >"$src/pe_${n}.c" <<EOF
__declspec(dllimport) const char *syft_${n}_identity(void);
int main(void) {
    return syft_${n}_identity()[0] == 's' ? 0 : 1;
}
EOF

  cat >"$src/syft${n}.rc" <<EOF
1 VERSIONINFO
FILEVERSION     1,0,${upper},0
PRODUCTVERSION  1,0,${upper},0
FILEFLAGSMASK   0x3fL
FILEFLAGS       0x0L
FILEOS          0x40004L
FILETYPE        0x2L
FILESUBTYPE     0x0L
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904b0"
        BEGIN
            VALUE "FileVersion", "1.0.${upper}.0"
            VALUE "ProductVersion", "1.0.${upper}.0"
            VALUE "OriginalFilename", "syft${n}-1.dll"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x409, 1200
    END
END
EOF

  "$pe_windres" "$src/syft${n}.rc" -O coff -o "$src/syft${n}.res.o"
  "$pe_cc" -O2 -shared \
    "$src/syft${n}.c" "$src/syft${n}.res.o" \
    -o "$libraries/syft${n}-1.dll" \
    -Wl,--out-implib,"$libraries/libsyft${n}.dll.a"

  "$pe_cc" -O2 \
    -o "$programs/pe_${n}.exe" \
    "$src/pe_${n}.c" \
    -L"$libraries" -lsyft${n}
done

rm -f "$src"/*.res.o
rm -f "$libraries"/*.dll.a
# Case 10's runtime DLL is removed after its executable has been linked.
rm -f "$libraries/syft10-1.dll"

echo "built 10 binary fixtures in $programs"
