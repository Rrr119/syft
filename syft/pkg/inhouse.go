package pkg

import "github.com/anchore/syft/syft/file"

// InHouseArtifact represents a first-party (in-house / proprietary) build artifact that is
// declared by an organization's own build system in an in-house artifact manifest.
type InHouseArtifact struct {
	// Kind is a free-form classification of the artifact (e.g. "application", "library", "firmware")
	Kind string `json:"kind,omitempty"`

	// Description is a human-readable summary of the artifact
	Description string `json:"description,omitempty"`

	// Supplier is the organization or team that produced the artifact
	Supplier string `json:"supplier,omitempty"`

	// Checksums are cryptographic digests of the built artifact
	Checksums []file.Digest `json:"checksums,omitempty"`

	// Paths are the locations within the scanned target where the artifact is deployed
	Paths []string `json:"paths,omitempty"`
}
