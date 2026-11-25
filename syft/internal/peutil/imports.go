package peutil

import (
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

const (
	importDirectoryIndex      = 1
	maxImportDescriptors      = 4096
	maxImportLibraryNameBytes = 4096
)

// ImportedLibraries returns the DLL names from a PE import directory.
//
// debug/pe.File.ImportedLibraries is currently unimplemented and always returns
// nil, so syft needs its own small parser for the descriptor array.
func ImportedLibraries(f *pe.File) ([]string, error) {
	if f == nil || f.OptionalHeader == nil {
		return nil, nil
	}

	directory, ok := dataDirectory(f, importDirectoryIndex)
	if !ok || directory.VirtualAddress == 0 {
		return nil, nil
	}

	section, offset, err := sectionForRVA(f, directory.VirtualAddress)
	if err != nil {
		return nil, err
	}

	sectionReader := section.Open()
	if _, err := sectionReader.Seek(int64(offset), io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek PE import directory: %w", err)
	}

	limit := maxImportDescriptors
	if directory.Size >= 20 {
		if descriptors := int(directory.Size / 20); descriptors < limit {
			limit = descriptors
		}
	}

	seen := make(map[string]struct{})
	var libraries []string
	descriptor := make([]byte, 20)

	for range limit {
		if _, err := io.ReadFull(sectionReader, descriptor); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
			return nil, fmt.Errorf("read PE import descriptor: %w", err)
		}

		nameRVA := binary.LittleEndian.Uint32(descriptor[12:16])
		if nameRVA == 0 {
			break
		}

		name, err := readCStringAtRVA(f, nameRVA)
		if err != nil {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}

		key := strings.ToLower(name)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		libraries = append(libraries, name)
	}

	sort.Strings(libraries)
	return libraries, nil
}

func dataDirectory(f *pe.File, index int) (pe.DataDirectory, bool) {
	switch header := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if index >= len(header.DataDirectory) {
			return pe.DataDirectory{}, false
		}
		return header.DataDirectory[index], true
	case *pe.OptionalHeader64:
		if index >= len(header.DataDirectory) {
			return pe.DataDirectory{}, false
		}
		return header.DataDirectory[index], true
	default:
		return pe.DataDirectory{}, false
	}
}

func sectionForRVA(f *pe.File, rva uint32) (*pe.Section, uint32, error) {
	for _, section := range f.Sections {
		size := section.VirtualSize
		if size == 0 {
			size = section.Size
		}
		start := uint64(section.VirtualAddress)
		if uint64(rva) >= start && uint64(rva)-start < uint64(size) {
			return section, rva - section.VirtualAddress, nil
		}
	}
	return nil, 0, fmt.Errorf("PE RVA %#x is outside all sections", rva)
}

func readCStringAtRVA(f *pe.File, rva uint32) (string, error) {
	section, offset, err := sectionForRVA(f, rva)
	if err != nil {
		return "", err
	}

	reader := section.Open()
	if _, err := reader.Seek(int64(offset), io.SeekStart); err != nil {
		return "", fmt.Errorf("seek PE library name: %w", err)
	}

	buffer := make([]byte, maxImportLibraryNameBytes)
	n, err := reader.Read(buffer)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read PE library name: %w", err)
	}
	buffer = buffer[:n]

	if end := strings.IndexByte(string(buffer), 0); end >= 0 {
		buffer = buffer[:end]
	}
	return string(buffer), nil
}
