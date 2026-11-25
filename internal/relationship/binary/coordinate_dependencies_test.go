package binary

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

func TestResolveCoordinateDependencies(t *testing.T) {
	subject := file.NewCoordinates("/programs/pe_07.exe", "")

	parent := pkg.Package{
		Name:    "pe_07.exe",
		Version: "1.0.0",
		Type:    pkg.BinaryPkg,
		Locations: file.NewLocationSet(
			file.NewLocation(subject.RealPath).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		),
	}
	parent.SetID()

	dependency := pkg.Package{Name: "syft07-1", Version: "1.0.7.0", Type: pkg.BinaryPkg}
	dependency.SetID()

	coordinateRelationship := artifact.Relationship{
		From: dependency,
		To:   subject,
		Type: artifact.DependencyOfRelationship,
	}

	accessor := newAccessor(
		[]pkg.Package{parent, dependency},
		nil,
		[]artifact.Relationship{coordinateRelationship},
	)

	got := ResolveCoordinateDependencies(accessor)
	require.Len(t, got, 1)
	assert.Equal(t, dependency.ID(), got[0].From.ID())
	assert.Equal(t, parent.ID(), got[0].To.ID())
	assert.Equal(t, artifact.DependencyOfRelationship, got[0].Type)

	var remaining []artifact.Relationship
	accessor.ReadFromSBOM(func(s *sbom.SBOM) {
		remaining = s.Relationships
	})

	require.Len(t, remaining, 1)
	assert.Equal(t, parent.ID(), remaining[0].To.ID())
}

func TestResolveCoordinateDependenciesWithoutParentRetainsEdge(t *testing.T) {
	subject := file.NewCoordinates("/programs/elf_01", "")
	dependency := pkg.Package{Name: "libsyft01.so", Version: "1.1.0", Type: pkg.BinaryPkg}
	dependency.SetID()

	coordinateRelationship := artifact.Relationship{
		From: dependency,
		To:   subject,
		Type: artifact.DependencyOfRelationship,
	}

	accessor := newAccessor(
		[]pkg.Package{dependency},
		nil,
		[]artifact.Relationship{coordinateRelationship},
	)

	assert.Empty(t, ResolveCoordinateDependencies(accessor))

	var remaining []artifact.Relationship
	accessor.ReadFromSBOM(func(s *sbom.SBOM) {
		remaining = s.Relationships
	})
	require.Len(t, remaining, 1)
	assert.Equal(t, subject.ID(), remaining[0].To.ID())
}
