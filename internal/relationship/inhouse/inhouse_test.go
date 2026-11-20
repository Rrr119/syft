package inhouse

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

func testPackage(p pkg.Package) pkg.Package {
	p.SetID()
	return p
}

func inHousePackage(name, version string, paths ...string) pkg.Package {
	return testPackage(pkg.Package{
		Name:      name,
		Version:   version,
		Locations: file.NewLocationSet(file.NewLocation("/opt/acme/inhouse-manifest.json")),
		Type:      pkg.InHousePkg,
		Metadata: pkg.InHouseArtifact{
			Paths: paths,
		},
	})
}

func TestPackagesToRemove(t *testing.T) {
	apkCurl := testPackage(pkg.Package{
		Name:      "curl",
		Version:   "8.12.1-r0",
		Locations: file.NewLocationSet(file.NewLocation("/lib/apk/db/installed")),
		Type:      pkg.ApkPkg,
	})

	inHouseCurl := inHousePackage("curl", "8.12.1-r0")
	inHouseCurlOtherVersion := inHousePackage("curl", "1.0.0")

	binaryGateway := testPackage(pkg.Package{
		Name: "acme-gateway",
		Locations: file.NewLocationSet(
			file.NewLocation("/opt/acme/bin/gateway").WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		),
		Type: pkg.BinaryPkg,
	})

	binaryUnrelated := testPackage(pkg.Package{
		Name: "unrelated",
		Locations: file.NewLocationSet(
			file.NewLocation("/usr/bin/unrelated").WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		),
		Type: pkg.BinaryPkg,
	})

	inHouseGateway := inHousePackage("acme-gateway", "2.3.1", "/opt/acme/bin/gateway")
	inHouseGatewayDup := inHousePackage("acme-gateway", "2.3.1", "/other/path/gateway")
	inHouseUnique := inHousePackage("acme-sidecar", "1.0.0", "/opt/acme/lib/sidecar.so")

	tests := []struct {
		name     string
		pkgs     []pkg.Package
		expected []artifact.ID
	}{
		{
			name:     "no in-house packages",
			pkgs:     []pkg.Package{apkCurl, binaryUnrelated},
			expected: nil,
		},
		{
			name:     "in-house package already represented by package manager package",
			pkgs:     []pkg.Package{apkCurl, inHouseCurl},
			expected: []artifact.ID{inHouseCurl.ID()},
		},
		{
			name:     "in-house package with different version is kept",
			pkgs:     []pkg.Package{apkCurl, inHouseCurlOtherVersion},
			expected: nil,
		},
		{
			name:     "binary package represented by in-house manifest by name",
			pkgs:     []pkg.Package{binaryGateway, inHouseUnique, inHousePackage("acme-gateway", "9.9.9")},
			expected: []artifact.ID{binaryGateway.ID()},
		},
		{
			name:     "binary package represented by in-house manifest by deployed path",
			pkgs:     []pkg.Package{binaryGateway, inHouseGateway},
			expected: []artifact.ID{binaryGateway.ID()},
		},
		{
			name:     "unrelated binary package is kept",
			pkgs:     []pkg.Package{binaryUnrelated, inHouseGateway},
			expected: nil,
		},
		{
			name:     "duplicate in-house packages across manifests are deduplicated",
			pkgs:     []pkg.Package{inHouseGateway, inHouseGatewayDup},
			expected: []artifact.ID{inHouseGatewayDup.ID()},
		},
		{
			name:     "unique in-house package is kept",
			pkgs:     []pkg.Package{apkCurl, inHouseUnique},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sb := sbom.SBOM{
				Artifacts: sbom.Artifacts{
					Packages: pkg.NewCollection(),
				},
			}
			builder := sbomsync.NewBuilder(&sb)
			builder.AddPackages(tt.pkgs...)

			actual := PackagesToRemove(builder.(sbomsync.Accessor))

			assert.ElementsMatch(t, tt.expected, actual)
		})
	}
}

func TestPackagesToRemoveDeterministic(t *testing.T) {
	first := inHousePackage("acme-gateway", "2.3.1", "/a")
	second := inHousePackage("acme-gateway", "2.3.1", "/b")

	removed := func(pkgs ...pkg.Package) []artifact.ID {
		sb := sbom.SBOM{
			Artifacts: sbom.Artifacts{
				Packages: pkg.NewCollection(),
			},
		}
		builder := sbomsync.NewBuilder(&sb)
		builder.AddPackages(pkgs...)
		return PackagesToRemove(builder.(sbomsync.Accessor))
	}

	forward := removed(first, second)
	reverse := removed(second, first)

	require.Len(t, forward, 1)
	require.Len(t, reverse, 1)
	assert.Equal(t, forward, reverse)
}
