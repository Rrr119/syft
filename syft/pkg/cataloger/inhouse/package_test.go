package inhouse

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/file"
)

func TestMergeEntries(t *testing.T) {
	entries := []manifestEntry{
		{
			Name:     "dup",
			Version:  "1.0.0",
			Licenses: []string{"MIT"},
			Paths:    []string{"/a"},
		},
		{
			Name:      "dup",
			Version:   "1.0.0",
			Supplier:  "Acme Corp",
			Licenses:  []string{"MIT", "Apache-2.0"},
			Paths:     []string{"/a", "/b"},
			Checksums: []file.Digest{{Algorithm: "sha256", Value: "abc"}},
		},
		{
			Name:    "dup",
			Version: "2.0.0", // different version: not merged
		},
	}

	merged := mergeEntries(entries)

	assert.Len(t, merged, 2)

	first := merged[0]
	assert.Equal(t, "Acme Corp", first.Supplier)
	assert.Equal(t, []string{"MIT", "Apache-2.0"}, first.Licenses)
	assert.Equal(t, []string{"/a", "/b"}, first.Paths)
	assert.Equal(t, []file.Digest{{Algorithm: "sha256", Value: "abc"}}, first.Checksums)
}
