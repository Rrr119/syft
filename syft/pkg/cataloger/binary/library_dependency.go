package binary

import (
	"debug/pe"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/elfutil"
	"github.com/anchore/syft/syft/internal/peutil"
)

// LibraryReference is a dynamic-library dependency claimed by an ELF or PE binary.
type LibraryReference struct {
	// Reference is the library name exactly as found in DT_NEEDED or the PE import table.
	Reference string `json:"reference"`

	// Format is the executable format that contained the reference.
	Format file.ExecutableFormat `json:"format"`

	// Name is the file-derived library name with any embedded ABI/version suffix removed.
	Name string `json:"name"`

	// Version is the best version that can be derived from the reference itself.
	Version string `json:"version,omitempty"`
}

var dottedVersionPattern = regexp.MustCompile(`^\d+(?:\.\d+)*$`)

var peArchitectureSuffixes = map[string]struct{}{
	"x86":     {},
	"x64":     {},
	"amd64":   {},
	"i386":    {},
	"i686":    {},
	"ia64":    {},
	"arm":     {},
	"arm64":   {},
	"aarch64": {},
	"win32":   {},
	"win64":   {},
}

// ParseLibraryReferences reads the dynamic library references from an ELF or PE binary.
func ParseLibraryReferences(r io.ReaderAt) ([]LibraryReference, file.ExecutableFormat, error) {
	if refs, err := parseELFLibraryReferences(r); err == nil && refs != nil {
		return refs, file.ELF, nil
	} else if err != nil && !isUnrecognizedBinaryError(err) {
		// debug/elf returns a generic format error for non-ELF files, so try PE before returning.
		if refs, peErr := parsePELibraryReferences(r); peErr == nil {
			return refs, file.PE, nil
		}
		return nil, "", err
	}

	refs, err := parsePELibraryReferences(r)
	if err != nil {
		return nil, "", err
	}
	return refs, file.PE, nil
}

func parseELFLibraryReferences(r io.ReaderAt) ([]LibraryReference, error) {
	f, err := elfutil.NewFile(r)
	if err != nil {
		return nil, err
	}

	imported, err := f.ImportedLibraries()
	if err != nil {
		return nil, err
	}

	return newLibraryReferences(imported, file.ELF), nil
}

func parsePELibraryReferences(r io.ReaderAt) ([]LibraryReference, error) {
	f, err := pe.NewFile(r)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	imported, err := peutil.ImportedLibraries(f)
	if err != nil || len(imported) == 0 {
		// Keep a fallback for Go/debug/pe behavior changes and binaries whose import descriptors are
		// unusual but whose symbol names still identify their source DLL.
		if symbols, symbolErr := f.ImportedSymbols(); symbolErr == nil {
			if names := dllNamesFromImportedSymbols(symbols); len(names) > 0 {
				imported = names
				err = nil
			}
		}
	}
	if err != nil {
		return nil, err
	}

	return newLibraryReferences(imported, file.PE), nil
}

func dllNamesFromImportedSymbols(symbols []string) []string {
	seen := make(map[string]struct{})
	var libraries []string
	for _, symbol := range symbols {
		idx := strings.LastIndex(symbol, ":")
		if idx < 0 || idx == len(symbol)-1 {
			continue
		}
		name := symbol[idx+1:]
		key := strings.ToLower(name)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		libraries = append(libraries, name)
	}
	sort.Strings(libraries)
	return libraries
}

func newLibraryReferences(names []string, format file.ExecutableFormat) []LibraryReference {
	seen := make(map[string]struct{}, len(names))
	refs := make([]LibraryReference, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		key := strings.ToLower(name)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		libName, version := ParseLibraryReference(name, format)
		refs = append(refs, LibraryReference{
			Reference: name,
			Format:    format,
			Name:      libName,
			Version:   version,
		})
	}
	return refs
}

// ParseLibraryReference derives a stable library name and any version embedded in its file name.
//
// The version returned here is intentionally limited to evidence in the reference. A SONAME ABI
// version such as "6" is returned because SBOM consumers use it to distinguish incompatible library
// generations; callers should prefer a version resource or package note from the resolved file.
func ParseLibraryReference(reference string, format file.ExecutableFormat) (string, string) {
	base := path.Base(strings.ReplaceAll(reference, "\\", "/"))

	switch format {
	case file.ELF:
		return parseELFLibraryFileName(base)
	case file.PE:
		return parsePELibraryFileName(base)
	default:
		name := strings.TrimSuffix(base, path.Ext(base))
		return name, ""
	}
}

func parseELFLibraryFileName(base string) (string, string) {
	if i := strings.Index(base, ".so."); i >= 0 {
		version := base[i+len(".so."):]
		name := base[:i] + ".so"
		if !dottedVersionPattern.MatchString(version) {
			return base, ""
		}
		return name, version
	}

	if strings.HasSuffix(base, ".so") {
		return base, ""
	}

	// Some loaders and linker scripts are referenced as e.g. "ld-linux-x86-64.so.2"; the branch above
	// handles the normal ".so.N" form. Names without ".so" are still useful as literal references.
	return base, ""
}

func parsePELibraryFileName(base string) (string, string) {
	ext := path.Ext(base)
	if strings.EqualFold(ext, ".dll") || strings.EqualFold(ext, ".exe") || strings.EqualFold(ext, ".bpl") {
		base = base[:len(base)-len(ext)]
	}

	parts := strings.Split(base, "-")
	for len(parts) > 1 {
		last := strings.ToLower(parts[len(parts)-1])
		if _, ok := peArchitectureSuffixes[last]; ok {
			parts = parts[:len(parts)-1]
			continue
		}
		break
	}

	if len(parts) > 1 && dottedVersionPattern.MatchString(parts[len(parts)-1]) {
		return strings.Join(parts[:len(parts)-1], "-"), parts[len(parts)-1]
	}

	return base, ""
}

func isUnrecognizedBinaryError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "bad magic") ||
		strings.Contains(msg, "invalid ELF header") ||
		strings.Contains(msg, "unrecognized ELF")
}
