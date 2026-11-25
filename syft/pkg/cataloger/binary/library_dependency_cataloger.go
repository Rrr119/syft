package binary

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"
	"unicode"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/mimetype"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/unionreader"
	"github.com/anchore/syft/syft/pkg"
	dotnetpe "github.com/anchore/syft/syft/pkg/cataloger/internal/dotnet/pe"
)

var _ pkg.Cataloger = (*binaryDependencyCataloger)(nil)

type binaryDependencyCataloger struct{}

// NewBinaryDependencyCataloger returns a cataloger that records libraries imported by ELF and PE binaries.
//
// Unlike the ELF package-notes and PE version-resource catalogers, this cataloger works even when the
// binary or its imported library has no package metadata. Versions are taken conservatively from the
// import name, a resolved library file name, ELF package notes, or PE version resources.
func NewBinaryDependencyCataloger() pkg.Cataloger {
	return &binaryDependencyCataloger{}
}

// NewLibraryDependencyCataloger is an alias for NewBinaryDependencyCataloger.
func NewLibraryDependencyCataloger() pkg.Cataloger {
	return NewBinaryDependencyCataloger()
}

func (c *binaryDependencyCataloger) Name() string {
	return "binary-dependency-cataloger"
}

func (c *binaryDependencyCataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	locations, err := resolver.FilesByMIMEType(mimetype.ExecutableMIMETypeSet.List()...)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get binary files by mime type: %w", err)
	}

	var packages []pkg.Package
	var relationships []artifact.Relationship

	for _, location := range locations {
		refs, err := c.libraryReferences(resolver, location)
		if err != nil {
			log.WithFields("file", location.FullNestedPath(), "error", err).Trace("unable to read binary library dependencies")
			continue
		}

		for _, ref := range refs {
			for _, p := range c.packagesForReference(ctx, resolver, ref) {
				p.SetID()

				packages = append(packages, p)
				relationships = append(relationships, artifact.Relationship{
					From: p,
					To:   location.Coordinates,
					Type: artifact.DependencyOfRelationship,
				})
			}
		}
	}

	return packages, relationships, nil
}

func (c *binaryDependencyCataloger) libraryReferences(resolver file.Resolver, location file.Location) ([]LibraryReference, error) {
	reader, err := resolver.FileContentsByLocation(location)
	if err != nil {
		return nil, fmt.Errorf("unable to open binary: %w", err)
	}
	defer internal.CloseAndLogError(reader, location.FullNestedPath())

	unionReader, err := unionreader.GetUnionReader(reader)
	if err != nil {
		return nil, err
	}

	refs, _, err := ParseLibraryReferences(unionReader)
	return refs, err
}

func (c *binaryDependencyCataloger) packagesForReference(ctx context.Context, resolver file.Resolver, ref LibraryReference) []pkg.Package {
	p := pkg.Package{
		Name:    ref.Name,
		Version: ref.Version,
		Type:    pkg.BinaryPkg,
		PURL:    libraryPackageURL(ref.Name, ref.Version),
	}

	if resolver == nil {
		return []pkg.Package{p}
	}

	candidates := c.resolveLibraryLocations(resolver, ref)
	locationSet := file.NewLocationSet()
	var metadataPackages []pkg.Package

	for _, candidate := range candidates {
		if metadataPkg, ok := c.packageFromLibraryMetadata(ctx, resolver, candidate); ok {
			metadataPackages = append(metadataPackages, metadataPkg)
			continue
		}

		_, candidateVersion := ParseLibraryReference(path.Base(candidate.FullNestedPath()), ref.Format)
		if compareDottedVersions(candidateVersion, p.Version) > 0 {
			p.Version = candidateVersion
		}
		locationSet.Add(candidate.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))
	}

	if !locationSet.Empty() {
		p.Locations = locationSet
	}
	p.PURL = libraryPackageURL(p.Name, p.Version)

	if len(metadataPackages) > 0 {
		return metadataPackages
	}
	return []pkg.Package{p}
}

func (c *binaryDependencyCataloger) resolveLibraryLocations(resolver file.Resolver, ref LibraryReference) []file.Location {
	basename := path.Base(ref.Reference)
	if basename == "" || basename == "." || basename == "/" {
		return nil
	}

	patterns := []string{"**/" + basename}
	if ref.Format == file.PE {
		patterns = append(patterns, "**/"+caseInsensitiveGlob(basename))
	}
	if ref.Format == file.ELF && strings.Contains(basename, ".so.") {
		patterns = append(patterns, "**/"+basename+".*")
	}

	seen := make(map[file.Coordinates]struct{})
	var locations []file.Location
	for _, pattern := range patterns {
		matches, err := resolver.FilesByGlob(pattern)
		if err != nil {
			log.WithFields("glob", pattern, "error", err).Trace("unable to resolve imported library path")
			continue
		}
		for _, location := range matches {
			base := path.Base(location.FullNestedPath())
			if !libraryCandidateMatches(base, basename, ref.Format) {
				continue
			}
			if _, ok := seen[location.Coordinates]; ok {
				continue
			}
			seen[location.Coordinates] = struct{}{}
			locations = append(locations, location)
		}
	}

	sort.Slice(locations, func(i, j int) bool {
		return locations[i].FullNestedPath() < locations[j].FullNestedPath()
	})

	return locations
}

func caseInsensitiveGlob(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) {
			b.WriteRune('[')
			b.WriteRune(unicode.ToLower(r))
			b.WriteRune(unicode.ToUpper(r))
			b.WriteRune(']')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func libraryCandidateMatches(candidateBase, referenceBase string, format file.ExecutableFormat) bool {
	if candidateBase == referenceBase {
		return true
	}
	if format != file.ELF {
		return strings.EqualFold(candidateBase, referenceBase)
	}

	// DT_NEEDED frequently names the SONAME symlink (libfoo.so.1) while the real file carries the full
	// version (libfoo.so.1.2.3).
	return strings.HasPrefix(candidateBase, referenceBase+".") &&
		dottedVersionPattern.MatchString(strings.TrimPrefix(candidateBase, referenceBase+"."))
}

func (c *binaryDependencyCataloger) packageFromLibraryMetadata(ctx context.Context, resolver file.Resolver, location file.Location) (pkg.Package, bool) {
	if p, ok := c.elfPackageFromLocation(ctx, resolver, location); ok {
		return p, true
	}
	if p, ok := c.pePackageFromLocation(resolver, location); ok {
		return p, true
	}
	return pkg.Package{}, false
}

func (c *binaryDependencyCataloger) elfPackageFromLocation(ctx context.Context, resolver file.Resolver, location file.Location) (pkg.Package, bool) {
	reader, err := resolver.FileContentsByLocation(location)
	if err != nil {
		return pkg.Package{}, false
	}
	defer internal.CloseAndLogError(reader, location.FullNestedPath())

	notes, err := getELFNotes(file.LocationReadCloser{Location: location, ReadCloser: reader})
	if err != nil || notes == nil || notes.Name == "" || notes.Version == "" {
		return pkg.Package{}, false
	}

	locations := file.NewLocationSet(location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))
	return newELFPackage(ctx, *notes, locations), true
}

func (c *binaryDependencyCataloger) pePackageFromLocation(resolver file.Resolver, location file.Location) (pkg.Package, bool) {
	reader, err := resolver.FileContentsByLocation(location)
	if err != nil {
		return pkg.Package{}, false
	}
	defer internal.CloseAndLogError(reader, location.FullNestedPath())

	peFile, err := dotnetpe.Read(file.LocationReadCloser{Location: location, ReadCloser: reader})
	if err != nil || peFile == nil || (peFile.CLR != nil && peFile.CLR.HasEvidenceOfCLR()) {
		return pkg.Package{}, false
	}

	return newPEPackage(peFile.VersionResources, location), true
}

func compareDottedVersions(a, b string) int {
	if a == b {
		return 0
	}
	if a == "" {
		return -1
	}
	if b == "" {
		return 1
	}

	pa := strings.Split(a, ".")
	pb := strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var na, nb int
		if i < len(pa) {
			_, _ = fmt.Sscanf(pa[i], "%d", &na)
		}
		if i < len(pb) {
			_, _ = fmt.Sscanf(pb[i], "%d", &nb)
		}
		if na != nb {
			if na < nb {
				return -1
			}
			return 1
		}
	}
	return 0
}

func libraryPackageURL(name, version string) string {
	if name == "" || version == "" {
		return ""
	}
	return packageurl.NewPackageURL(
		packageurl.TypeGeneric,
		"",
		strings.ToLower(name),
		version,
		nil,
		"",
	).ToString()
}
