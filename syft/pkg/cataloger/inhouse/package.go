package inhouse

import (
	"context"
	"sort"

	"github.com/anchore/packageurl-go"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newInHousePackage(ctx context.Context, entry manifestEntry, location file.Location) pkg.Package {
	sort.Strings(entry.Paths)

	p := pkg.Package{
		Name:      entry.Name,
		Version:   entry.Version,
		Locations: file.NewLocationSet(location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		Type:      pkg.InHousePkg,
		Metadata: pkg.InHouseArtifact{
			Kind:        entry.Kind,
			Description: entry.Description,
			Supplier:    entry.Supplier,
			Checksums:   entry.Checksums,
			Paths:       entry.Paths,
		},
	}

	for _, license := range entry.Licenses {
		p.Licenses.Add(pkg.NewLicenseWithContext(ctx, license))
	}

	for _, cpeStr := range entry.CPEs {
		value, err := cpe.New(cpeStr, cpe.DeclaredSource)
		if err != nil {
			log.WithFields("name", entry.Name, "cpe", cpeStr).Debug("unable to parse CPE from in-house artifact manifest")
			continue
		}
		p.CPEs = append(p.CPEs, value)
	}

	if entry.PURL != "" {
		p.PURL = entry.PURL
	} else {
		p.PURL = packageurl.NewPackageURL(packageurl.TypeGeneric, "", entry.Name, entry.Version, nil, "").ToString()
	}

	p.SetID()

	return p
}
