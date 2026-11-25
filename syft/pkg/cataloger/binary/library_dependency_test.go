package binary

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
)

func TestParseLibraryReference(t *testing.T) {
	tests := []struct {
		name        string
		reference   string
		format      file.ExecutableFormat
		wantName    string
		wantVersion string
	}{
		{name: "elf full version", reference: "libz.so.1.2.11", format: file.ELF, wantName: "libz.so", wantVersion: "1.2.11"},
		{name: "elf abi version", reference: "libc.so.6", format: file.ELF, wantName: "libc.so", wantVersion: "6"},
		{name: "elf no version", reference: "libz.so", format: file.ELF, wantName: "libz.so", wantVersion: ""},
		{name: "elf loader", reference: "ld-linux-x86-64.so.2", format: file.ELF, wantName: "ld-linux-x86-64.so", wantVersion: "2"},
		{name: "elf non numeric suffix is literal", reference: "libfoo.so.debug", format: file.ELF, wantName: "libfoo.so.debug", wantVersion: ""},
		{name: "pe version and arch", reference: "libcrypto-3-x64.dll", format: file.PE, wantName: "libcrypto", wantVersion: "3"},
		{name: "pe dotted version", reference: "vendor-runtime-1.2.3.dll", format: file.PE, wantName: "vendor-runtime", wantVersion: "1.2.3"},
		{name: "pe system library", reference: "KERNEL32.dll", format: file.PE, wantName: "KERNEL32", wantVersion: ""},
		{name: "pe exe extension", reference: "server-2.exe", format: file.PE, wantName: "server", wantVersion: "2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotVersion := ParseLibraryReference(tt.reference, tt.format)
			assert.Equal(t, tt.wantName, gotName)
			assert.Equal(t, tt.wantVersion, gotVersion)
		})
	}
}

func TestCaseInsensitiveGlob(t *testing.T) {
	assert.Equal(t, "[kK][eE][rR][nN][eE][lL]32.[dD][lL][lL]", caseInsensitiveGlob("kernel32.DLL"))
}

type dependencyExpectation struct {
	name    string
	version string
}

func skipWithoutTenBinaryFixtures(t *testing.T) string {
	t.Helper()
	fixture := "testdata/library-dependencies"
	if _, err := os.Stat(filepath.Join(fixture, "programs", "elf_01")); err != nil {
		t.Skipf("compiled binary fixtures are unavailable: %v", err)
	}
	return fixture
}

func TestLibraryDependencyCatalogerTenManuallyVerifiedBinaries(t *testing.T) {
	fixture := skipWithoutTenBinaryFixtures(t)

	src, err := directorysource.NewFromPath(fixture)
	require.NoError(t, err)
	resolver, err := src.FileResolver(source.AllLayersScope)
	require.NoError(t, err)

	cataloger := NewLibraryDependencyCataloger()
	packages, relationships, err := cataloger.Catalog(context.Background(), resolver)
	require.NoError(t, err)
	require.NotEmpty(t, packages)

	expected := map[string][]dependencyExpectation{
		"elf_01": {
			{name: "libsyft01.so", version: "1.1.0"},
			{name: "libc.so", version: "6"},
		},
		"elf_02": {
			{name: "libsyft02.so", version: "1.2.0"},
			{name: "libc.so", version: "6"},
		},
		"elf_03": {
			{name: "libsyft03.so", version: "1.3.0"},
			{name: "libc.so", version: "6"},
		},
		"elf_04": {
			{name: "libsyft04.so", version: "1.4.0"},
			{name: "libc.so", version: "6"},
		},
		"elf_05": {
			// The library was intentionally removed from the fixture; the DT_NEEDED ABI remains.
			{name: "libsyft05.so", version: "1"},
			{name: "libc.so", version: "6"},
		},
		"elf_06": {
			{name: "libsyft06.so", version: "1.6.0"},
			{name: "libc.so", version: "6"},
		},
		"pe_07.exe": {
			{name: "syft07-1", version: "1.0.7.0"},
			{name: "KERNEL32", version: ""},
			{name: "msvcrt", version: ""},
		},
		"pe_08.exe": {
			{name: "syft08-1", version: "1.0.8.0"},
			{name: "KERNEL32", version: ""},
			{name: "msvcrt", version: ""},
		},
		"pe_09.exe": {
			{name: "syft09-1", version: "1.0.9.0"},
			{name: "KERNEL32", version: ""},
			{name: "msvcrt", version: ""},
		},
		"pe_10.exe": {
			// The DLL was intentionally removed from the fixture; the import name still gives its ABI.
			{name: "syft10", version: "1"},
			{name: "KERNEL32", version: ""},
			{name: "msvcrt", version: ""},
		},
	}

	actual := make(map[string][]string)
	for _, rel := range relationships {
		coordinates, ok := rel.To.(file.Coordinates)
		if !ok || rel.Type != artifact.DependencyOfRelationship {
			continue
		}

		program := path.Base(coordinates.RealPath)
		if _, ok := expected[program]; !ok {
			continue
		}

		p, ok := rel.From.(pkg.Package)
		require.True(t, ok, "relationship From should be a package: %T", rel.From)
		actual[program] = append(actual[program], dependencyString(p.Name, p.Version))
	}

	require.Len(t, actual, len(expected), "should identify dependencies for all ten binaries")

	for program, deps := range expected {
		want := make([]string, 0, len(deps))
		for _, dep := range deps {
			want = append(want, dependencyString(dep.name, dep.version))
		}
		sort.Strings(want)

		got := append([]string(nil), actual[program]...)
		sort.Strings(got)
		assert.Equalf(t, want, got, "dependencies for manually verified binary %s", program)
	}
}

func dependencyString(name, version string) string {
	if version == "" {
		return name
	}
	return name + "@" + version
}

func TestLibraryDependencyCatalogerIsCompatibleWithExistingNames(t *testing.T) {
	c := NewLibraryDependencyCataloger()
	assert.Equal(t, "binary-dependency-cataloger", c.Name())
	assert.Equal(t, c.Name(), NewBinaryDependencyCataloger().Name())
	assert.True(t, strings.HasSuffix(NewELFPackageCataloger().Name(), "elf-binary-package-cataloger"))
	assert.True(t, strings.HasSuffix(NewPEPackageCataloger().Name(), "pe-binary-package-cataloger"))
}

func TestLibraryDependencyCatalogerMergesWithPEPackageCataloger(t *testing.T) {
	fixture := skipWithoutTenBinaryFixtures(t)
	src, err := directorysource.NewFromPath(fixture)
	require.NoError(t, err)
	resolver, err := src.FileResolver(source.AllLayersScope)
	require.NoError(t, err)

	dependencyPackages, _, err := NewLibraryDependencyCataloger().Catalog(context.Background(), resolver)
	require.NoError(t, err)

	pePackages, _, err := NewPEPackageCataloger().Catalog(context.Background(), resolver)
	require.NoError(t, err)

	collection := pkg.NewCollection()
	collection.Add(dependencyPackages...)
	collection.Add(pePackages...)

	matches := collection.PackagesByName("syft07-1")
	require.Len(t, matches, 1, "resolved PE dependency must merge with the existing PE package")
	assert.Equal(t, "1.0.7.0", matches[0].Version)
	assert.IsType(t, pkg.PEBinary{}, matches[0].Metadata)
}
