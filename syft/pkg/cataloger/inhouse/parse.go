package inhouse

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var _ generic.Parser = parseManifest

// manifest is the on-disk representation of an in-house artifact manifest. Build systems
// drop this file into a build artifact (e.g. a container image) to declare the first-party
// artifacts that were produced in-house and would otherwise be invisible to ecosystem catalogers.
type manifest struct {
	// Version is the schema version of the manifest itself (currently only "1" is supported)
	Version   int             `json:"version" yaml:"version"`
	Artifacts []manifestEntry `json:"artifacts" yaml:"artifacts"`
}

type manifestEntry struct {
	Name        string        `json:"name" yaml:"name"`
	Version     string        `json:"version" yaml:"version"`
	Kind        string        `json:"kind" yaml:"kind"`
	Description string        `json:"description" yaml:"description"`
	Supplier    string        `json:"supplier" yaml:"supplier"`
	Licenses    []string      `json:"licenses" yaml:"licenses"`
	PURL        string        `json:"purl" yaml:"purl"`
	CPEs        []string      `json:"cpes" yaml:"cpes"`
	Paths       []string      `json:"paths" yaml:"paths"`
	Checksums   []file.Digest `json:"checksums" yaml:"checksums"`
}

func parseManifest(ctx context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var m manifest

	var err error
	switch strings.ToLower(filepath.Ext(reader.Path())) {
	case ".yaml", ".yml":
		err = yaml.NewDecoder(reader).Decode(&m)
	default:
		err = json.NewDecoder(reader).Decode(&m)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse in-house artifact manifest %q: %w", reader.Path(), err)
	}

	if m.Version > 1 {
		log.WithFields("path", reader.Path(), "version", m.Version).Warn("unsupported in-house artifact manifest version, attempting to parse anyway")
	}

	var entries []manifestEntry
	for _, entry := range m.Artifacts {
		if entry.Name == "" || entry.Version == "" {
			log.WithFields("path", reader.Path(), "name", entry.Name, "version", entry.Version).Warn("skipping in-house artifact entry with missing name or version")
			continue
		}
		entries = append(entries, entry)
	}

	var pkgs []pkg.Package
	for _, entry := range mergeEntries(entries) {
		pkgs = append(pkgs, newInHousePackage(ctx, entry, reader.Location))
	}

	return pkgs, nil, unknown.IfEmptyf(pkgs, "unable to determine packages")
}

// mergeEntries deduplicates manifest entries by name and version, merging the remaining
// fields of duplicate entries into a single entry.
func mergeEntries(entries []manifestEntry) []manifestEntry {
	var out []manifestEntry
	indexByKey := make(map[string]int)

	for _, entry := range entries {
		key := entry.Name + "\x00" + entry.Version
		idx, exists := indexByKey[key]
		if !exists {
			indexByKey[key] = len(out)
			out = append(out, entry)
			continue
		}

		merged := &out[idx]
		if merged.Kind == "" {
			merged.Kind = entry.Kind
		}
		if merged.Description == "" {
			merged.Description = entry.Description
		}
		if merged.Supplier == "" {
			merged.Supplier = entry.Supplier
		}
		if merged.PURL == "" {
			merged.PURL = entry.PURL
		}
		merged.Licenses = mergeStrings(merged.Licenses, entry.Licenses)
		merged.CPEs = mergeStrings(merged.CPEs, entry.CPEs)
		merged.Paths = mergeStrings(merged.Paths, entry.Paths)
		merged.Checksums = mergeDigests(merged.Checksums, entry.Checksums)
	}

	return out
}

func mergeStrings(a, b []string) []string {
	seen := make(map[string]struct{}, len(a))
	for _, v := range a {
		seen[v] = struct{}{}
	}
	for _, v := range b {
		if _, ok := seen[v]; !ok {
			a = append(a, v)
			seen[v] = struct{}{}
		}
	}
	return a
}

func mergeDigests(a, b []file.Digest) []file.Digest {
	seen := make(map[file.Digest]struct{}, len(a))
	for _, v := range a {
		seen[v] = struct{}{}
	}
	for _, v := range b {
		if _, ok := seen[v]; !ok {
			a = append(a, v)
			seen[v] = struct{}{}
		}
	}
	return a
}
