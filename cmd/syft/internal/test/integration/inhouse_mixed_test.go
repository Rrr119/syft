package integration

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func TestInHouseMixedImage(t *testing.T) {
	// the fixture image mixes packages from a package manager (apk) with first-party
	// (in-house) build artifacts declared in an in-house artifact manifest:
	//  - acme-gateway: only present in the manifest
	//  - acme-sidecar: declared twice in the manifest (in-manifest dedup)
	//  - curl:         installed via apk AND declared in the manifest (cross-cataloger dedup)
	sbom, _ := catalogFixtureImage(t, "image-inhouse-mixed", source.SquashedScope)

	// in-house artifacts are cataloged alongside the apk packages
	var inHousePkgs []pkg.Package
	for _, p := range sbom.Artifacts.Packages.Sorted() {
		if p.Type == pkg.InHousePkg {
			inHousePkgs = append(inHousePkgs, p)
		}
	}
	require.Len(t, inHousePkgs, 2, "expected the 2 unique in-house artifacts (manifest entries deduplicated)")

	// the duplicate acme-sidecar manifest entries were merged into a single package
	sidecars := sbom.Artifacts.Packages.PackagesByName("acme-sidecar")
	require.Len(t, sidecars, 1)
	assert.Equal(t, "1.0.0", sidecars[0].Version)
	assert.Equal(t, pkg.InHousePkg, sidecars[0].Type)
	sidecarMeta, ok := sidecars[0].Metadata.(pkg.InHouseArtifact)
	require.True(t, ok)
	assert.Equal(t, "library", sidecarMeta.Kind)

	// the manifest-only artifact carries its declared metadata
	gateways := sbom.Artifacts.Packages.PackagesByName("acme-gateway")
	require.Len(t, gateways, 1)
	gatewayMeta, ok := gateways[0].Metadata.(pkg.InHouseArtifact)
	require.True(t, ok)
	assert.Equal(t, "Acme Corp", gatewayMeta.Supplier)
	assert.Equal(t, []string{"/opt/acme/bin/gateway"}, gatewayMeta.Paths)

	// curl is owned by apk; the in-house manifest entry duplicating it was removed
	curls := sbom.Artifacts.Packages.PackagesByName("curl")
	require.Len(t, curls, 1, "expected curl to be deduplicated across the apk DB and the in-house manifest")
	assert.Equal(t, pkg.ApkPkg, curls[0].Type)
}
