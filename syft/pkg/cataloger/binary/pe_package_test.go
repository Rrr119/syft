package binary

import (
	"testing"

	"github.com/anchore/syft/syft/file"
)

func TestGhostscriptPEGeneratesGenericPURL(t *testing.T) {
	vr := map[string]string{
		"CompanyName":     "Artifex Software, Inc.",
		"ProductName":     "GPL Ghostscript",
		"FileDescription": "Ghostscript Interpreter",
		"ProductVersion":  "9.54.0",
	}

	loc := file.NewLocation("/usr/bin/gswin64c.exe")
	p := newPEPackage(vr, loc)

	expected := "pkg:generic/ghostscript@9.54.0"
	if p.PURL != expected {
		t.Fatalf("expected purl %q, got %q", expected, p.PURL)
	}
}

func TestTrimBinaryExtension(t *testing.T) {
	tests := map[string]string{
		"syft07-1.dll": "syft07-1",
		"SERVER.EXE":   "SERVER",
		"plugin.BPL":   "plugin",
		"README.txt":   "README.txt",
	}

	for input, want := range tests {
		if got := trimBinaryExtension(input); got != want {
			t.Errorf("trimBinaryExtension(%q) = %q, want %q", input, got, want)
		}
	}
}
