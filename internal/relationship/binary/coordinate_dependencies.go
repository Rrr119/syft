package binary

import (
	"github.com/anchore/syft/internal/relationship"
	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

type coordinateProvider interface {
	GetCoordinates() file.Coordinates
}

// ResolveCoordinateDependencies upgrades dependency-of relationships whose target is a binary
// coordinate to package-to-package relationships when another cataloger produced a primary package
// for that binary. Coordinate edges are retained when no such package exists.
func ResolveCoordinateDependencies(accessor sbomsync.Accessor) []artifact.Relationship {
	var (
		relationships []artifact.Relationship
		removeEdges   = map[string]struct{}{}
	)

	accessor.ReadFromSBOM(func(s *sbom.SBOM) {
		primaryPackages := primaryPackagesByCoordinate(s)
		index := relationship.NewIndex(s.Relationships...)

		for _, rel := range s.Relationships {
			if rel.Type != artifact.DependencyOfRelationship {
				continue
			}

			coordinates, ok := coordinateTarget(rel.To)
			if !ok {
				continue
			}

			parents := primaryPackages[coordinates]
			if len(parents) == 0 {
				continue
			}

			removeEdges[relationshipKey(rel)] = struct{}{}

			from := rel.From
			if p := s.Artifacts.Packages.Package(rel.From.ID()); p != nil {
				from = *p
			}

			for _, parent := range parents {
				resolved := artifact.Relationship{
					From: from,
					To:   parent,
					Type: artifact.DependencyOfRelationship,
				}
				if index.Contains(resolved) {
					continue
				}
				index.Add(resolved)
				relationships = append(relationships, resolved)
			}
		}
	})

	if len(removeEdges) > 0 {
		accessor.WriteToSBOM(func(s *sbom.SBOM) {
			kept := s.Relationships[:0]
			for _, rel := range s.Relationships {
				if _, remove := removeEdges[relationshipKey(rel)]; remove {
					continue
				}
				kept = append(kept, rel)
			}
			s.Relationships = append(kept, relationships...)
		})
	}

	return relationships
}

func relationshipKey(rel artifact.Relationship) string {
	return string(rel.From.ID()) + ":" + string(rel.To.ID()) + ":" + string(rel.Type)
}

func primaryPackagesByCoordinate(s *sbom.SBOM) map[file.Coordinates][]pkg.Package {
	out := make(map[file.Coordinates][]pkg.Package)
	for _, p := range s.Artifacts.Packages.Sorted() {
		for _, location := range p.Locations.ToSlice() {
			if location.Annotations[pkg.EvidenceAnnotationKey] != pkg.PrimaryEvidenceAnnotation {
				continue
			}
			out[location.Coordinates] = append(out[location.Coordinates], p)
		}
	}
	return out
}

func coordinateTarget(target artifact.Identifiable) (file.Coordinates, bool) {
	switch v := target.(type) {
	case file.Coordinates:
		return v, true
	case *file.Coordinates:
		if v == nil {
			return file.Coordinates{}, false
		}
		return *v, true
	case coordinateProvider:
		return v.GetCoordinates(), true
	default:
		return file.Coordinates{}, false
	}
}
