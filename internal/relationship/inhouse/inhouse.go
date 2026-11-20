// Package inhouse implements deduplication between first-party (in-house) build artifacts
// declared in in-house artifact manifests and packages discovered by other catalogers.
package inhouse

import (
	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

// PackagesToRemove returns the IDs of packages that are already represented by a
// higher-fidelity package in the SBOM:
//
//  1. binary-classifier packages that are also described by an in-house artifact manifest
//     (matched by name, or by a deployed path declared in the manifest), since the
//     manifest is human-curated and carries richer metadata.
//  2. in-house packages that are already represented by a package manager package
//     (matched by name and version), since the package manager database is authoritative.
//  3. duplicate in-house packages (matched by name and version) declared across
//     multiple manifests, keeping the first occurrence.
func PackagesToRemove(accessor sbomsync.Accessor) []artifact.ID {
	var ids []artifact.ID
	accessor.ReadFromSBOM(func(s *sbom.SBOM) {
		ids = append(ids, packagesToRemove(s)...)
	})
	return ids
}

func packagesToRemove(s *sbom.SBOM) []artifact.ID {
	toRemove := strset.New()

	var inHousePkgs []pkg.Package
	for _, p := range s.Artifacts.Packages.Sorted() {
		if p.Type == pkg.InHousePkg {
			inHousePkgs = append(inHousePkgs, p)
		}
	}
	if len(inHousePkgs) == 0 {
		return nil
	}

	seenInHouse := make(map[string]artifact.ID)
	for _, inHousePkg := range inHousePkgs {
		// 3. deduplicate in-house packages against each other
		key := inHousePkg.Name + "\x00" + inHousePkg.Version
		if _, exists := seenInHouse[key]; exists {
			toRemove.Add(string(inHousePkg.ID()))
			continue
		}
		seenInHouse[key] = inHousePkg.ID()

		deployedPaths := deployedPathsOf(inHousePkg)

		for _, other := range s.Artifacts.Packages.Sorted() {
			if other.ID() == inHousePkg.ID() || other.Type == pkg.InHousePkg {
				continue
			}

			switch other.Type {
			case pkg.BinaryPkg:
				// 1. the in-house manifest is human-curated, so it wins over binary classifiers
				if other.Name == inHousePkg.Name || overlapsAny(primaryEvidencePaths(other), deployedPaths) {
					toRemove.Add(string(other.ID()))
				}
			default:
				// 2. package manager data is authoritative over manifest declarations
				if other.Name == inHousePkg.Name && other.Version == inHousePkg.Version {
					toRemove.Add(string(inHousePkg.ID()))
				}
			}
		}
	}

	var ids []artifact.ID
	for _, id := range toRemove.List() {
		ids = append(ids, artifact.ID(id))
	}
	return ids
}

func deployedPathsOf(p pkg.Package) *strset.Set {
	paths := strset.New()
	if m, ok := p.Metadata.(pkg.InHouseArtifact); ok {
		for _, path := range m.Paths {
			paths.Add(path)
		}
	}
	return paths
}

func primaryEvidencePaths(p pkg.Package) *strset.Set {
	paths := strset.New()
	for _, loc := range p.Locations.ToSlice() {
		if loc.Annotations[pkg.EvidenceAnnotationKey] == pkg.PrimaryEvidenceAnnotation {
			paths.Add(loc.Coordinates.RealPath)
		}
	}
	return paths
}

func overlapsAny(a, b *strset.Set) bool {
	for _, path := range a.List() {
		if b.Has(path) {
			return true
		}
	}
	return false
}
