package inhouse

import (
	"context"
	"testing"

	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseManifest(t *testing.T) {
	ctx := context.TODO()
	jsonFixture := "testdata/inhouse-manifest.json"
	yamlFixture := "testdata/inhouse-manifest.yaml"

	tests := []struct {
		name     string
		fixture  string
		expected []pkg.Package
	}{
		{
			name:    "json manifest with duplicate entries merged",
			fixture: jsonFixture,
			expected: []pkg.Package{
				{
					Name:      "acme-gateway",
					Version:   "2.3.1",
					PURL:      "pkg:generic/acme-gateway@2.3.1",
					Locations: file.NewLocationSet(file.NewLocation(jsonFixture)),
					Licenses:  pkg.NewLicenseSet(pkg.NewLicenseWithContext(ctx, "Proprietary")),
					Type:      pkg.InHousePkg,
					CPEs: []cpe.CPE{
						cpe.Must("cpe:2.3:a:acme:gateway:2.3.1:*:*:*:*:*:*:*", cpe.DeclaredSource),
					},
					Metadata: pkg.InHouseArtifact{
						Kind:        "application",
						Description: "edge gateway service",
						Supplier:    "Acme Corp",
						Checksums: []file.Digest{
							{
								Algorithm: "sha256",
								Value:     "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c",
							},
						},
						Paths: []string{"/opt/acme/bin/gateway"},
					},
				},
				{
					Name:      "acme-sidecar",
					Version:   "1.0.0",
					PURL:      "pkg:generic/acme-sidecar@1.0.0",
					Locations: file.NewLocationSet(file.NewLocation(jsonFixture)),
					Licenses: pkg.NewLicenseSet(
						pkg.NewLicenseWithContext(ctx, "MIT"),
						pkg.NewLicenseWithContext(ctx, "Apache-2.0"),
					),
					Type: pkg.InHousePkg,
					Metadata: pkg.InHouseArtifact{
						Kind:     "library",
						Supplier: "Acme Corp",
						Checksums: []file.Digest{
							{
								Algorithm: "sha256",
								Value:     "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
							},
						},
						Paths: []string{"/opt/acme/lib/sidecar.so", "/usr/lib/sidecar.so"},
					},
				},
			},
		},
		{
			name:    "yaml manifest",
			fixture: yamlFixture,
			expected: []pkg.Package{
				{
					Name:      "acme-cli",
					Version:   "0.9.0",
					PURL:      "pkg:generic/acme-cli@0.9.0",
					Locations: file.NewLocationSet(file.NewLocation(yamlFixture)),
					Licenses:  pkg.NewLicenseSet(pkg.NewLicenseWithContext(ctx, "Proprietary")),
					Type:      pkg.InHousePkg,
					Metadata: pkg.InHouseArtifact{
						Kind:     "application",
						Supplier: "Acme Corp",
						Paths:    []string{"/usr/local/bin/acme"},
					},
				},
			},
		},
		{
			name:    "entries with missing name or version are skipped",
			fixture: "testdata/invalid-entries/inhouse-manifest.json",
			expected: []pkg.Package{
				{
					Name:      "acme-worker",
					Version:   "3.2.1",
					PURL:      "pkg:generic/acme-worker@3.2.1",
					Locations: file.NewLocationSet(file.NewLocation("testdata/invalid-entries/inhouse-manifest.json")),
					Type:      pkg.InHousePkg,
					Metadata:  pkg.InHouseArtifact{},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.TestFileParser(t, test.fixture, parseManifest, test.expected, nil)
		})
	}
}
