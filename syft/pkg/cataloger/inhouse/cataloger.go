// Package inhouse provides a cataloger for first-party (in-house / proprietary) build artifacts
// declared by an organization's own build system in an in-house artifact manifest.
package inhouse

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const catalogerName = "inhouse-manifest-cataloger"

// NewCataloger returns a cataloger that surfaces first-party (in-house) build artifacts
// declared in in-house artifact manifests (e.g. inhouse-manifest.json or inhouse-manifest.yaml).
func NewCataloger() pkg.Cataloger {
	return generic.NewCataloger(catalogerName).
		WithParserByGlobs(parseManifest,
			"**/inhouse-manifest.json",
			"**/inhouse-manifest.yaml",
			"**/inhouse-manifest.yml",
			"**/.inhouse/manifest.json",
			"**/.inhouse/manifest.yaml",
			"**/.inhouse/manifest.yml",
		)
}
