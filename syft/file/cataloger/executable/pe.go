package executable

import (
	"debug/pe"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/peutil"
	"github.com/anchore/syft/syft/internal/unionreader"
)

func findPEFeatures(data *file.Executable, reader unionreader.UnionReader) error {
	// TODO: support security features

	f, err := pe.NewFile(reader)
	if err != nil {
		return err
	}

	libs, err := peutil.ImportedLibraries(f)
	if err != nil || len(libs) == 0 {
		// debug/pe derives DLL names while parsing symbols; retain this fallback for binaries with
		// import tables our focused parser does not accept.
		if symbols, symbolErr := f.ImportedSymbols(); symbolErr == nil {
			seen := make(map[string]struct{})
			for _, symbol := range symbols {
				if idx := strings.LastIndex(symbol, ":"); idx >= 0 && idx < len(symbol)-1 {
					name := symbol[idx+1:]
					key := strings.ToLower(name)
					if _, ok := seen[key]; !ok {
						seen[key] = struct{}{}
						libs = append(libs, name)
						err = nil
					}
				}
			}
		}
	}
	if err != nil {
		return err
	}

	data.ImportedLibraries = libs
	data.HasEntrypoint = peHasEntrypoint(f)
	data.HasExports = peHasExports(f)

	return nil
}

var (
	windowsExeEntrypoints = strset.New("main", "WinMain", "wWinMain")
	windowsDllEntrypoints = strset.New("DllMain", "_DllMainCRTStartup@12", "CRT_INIT")
)

func peHasEntrypoint(f *pe.File) bool {
	// DLLs can have entrypoints, but they are not "executables" in the traditional sense,
	// but instead point to an initialization function (DLLMain).
	// The PE format does not require an entrypoint, so it is possible to not have one, however,
	// the microsoft C runtime does: https://learn.microsoft.com/en-US/troubleshoot/developer/visualstudio/cpp/libraries/use-c-run-time
	//
	// > When building a DLL which uses any of the C Run-time libraries, in order to ensure that the CRT is properly initialized, either
	// > 1. the initialization function must be named DllMain() and the entry point must be specified with the linker option -entry:_DllMainCRTStartup@12 - or -
	// > 2. the DLL's entry point must explicitly call CRT_INIT() on process attach and process detach
	//
	// This isn't really helpful from a user perspective when it comes to indicating if there is an entrypoint or not
	// since it will always effectively be true for DLLs! All DLLs and Executables (aka "modules") have a single
	// entrypoint, _GetPEImageBase, but we're more interested in the logical idea of an entrypoint.
	// See https://learn.microsoft.com/en-us/windows/win32/psapi/module-information for more details.

	var hasLibEntrypoint, hasExeEntrypoint bool
	for _, s := range f.Symbols {
		if windowsExeEntrypoints.Has(s.Name) {
			hasExeEntrypoint = true
		}
		if windowsDllEntrypoints.Has(s.Name) {
			hasLibEntrypoint = true
		}
	}

	switch v := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return v.AddressOfEntryPoint > 0 && !hasLibEntrypoint && hasExeEntrypoint
	case *pe.OptionalHeader64:
		return v.AddressOfEntryPoint > 0 && !hasLibEntrypoint && hasExeEntrypoint
	}
	return false
}

func peHasExports(f *pe.File) bool {
	if f.OptionalHeader == nil {
		return false
	}

	switch v := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return v.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT].Size > 0
	case *pe.OptionalHeader64:
		return v.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT].Size > 0
	}

	return false
}
