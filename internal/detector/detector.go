package detector

import (
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
)

const headerReadSize = 65536

// Result describes the detected file type for an analyzed input.
type Result struct {
	Name        string
	Description string
	Extension   string
	Aliases     []string
	MIMEType    string
	Category    string
	Matched     bool
}

// UnknownResult returns the default result when no magic byte signature matches.
func UnknownResult() Result {
	return Result{
		Name:        "Unknown",
		Description: "Unknown file type",
		Category:    "Unknown",
		Matched:     false,
	}
}

// Pattern represents a byte sequence (with an optional bitmask) at a fixed offset.
type Pattern struct {
	Offset int64
	Value  []byte
	Mask   []byte
}

// Signature defines a file type detection rule.
type Signature struct {
	Name        string
	Description string
	Extension   string
	Aliases     []string
	MIMEType    string
	Category    string
	Patterns    []Pattern
	Priority    int
	Inspect     func(r io.ReadSeeker, size int64) (Result, bool)
}

var (
	sortedOnce       sync.Once
	sortedSignatures []Signature
)

func getSortedSignatures() []Signature {
	sortedOnce.Do(func() {
		sortedSignatures = make([]Signature, len(signaturesDB))
		copy(sortedSignatures, signaturesDB)
		sort.SliceStable(sortedSignatures, func(i, j int) bool {
			return sortedSignatures[i].Priority > sortedSignatures[j].Priority
		})
	})
	return sortedSignatures
}

// DetectFile opens the file at path and identifies its type via magic bytes.
func DetectFile(path string) (Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return Result{}, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return Result{}, fmt.Errorf("stat %s: %w", path, err)
	}
	if info.IsDir() {
		return Result{}, fmt.Errorf("%s is a directory", path)
	}

	return DetectReader(f, info.Size())
}

// DetectReader identifies the file type from an io.ReadSeeker of known size.
func DetectReader(r io.ReadSeeker, size int64) (Result, error) {
	if size == 0 {
		return UnknownResult(), nil
	}

	toRead := size
	if toRead > headerReadSize {
		toRead = headerReadSize
	}

	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return Result{}, fmt.Errorf("seek start: %w", err)
	}

	header := make([]byte, toRead)
	n, err := io.ReadFull(r, header)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return Result{}, fmt.Errorf("read header: %w", err)
	}
	header = header[:n]

	for _, sig := range getSortedSignatures() {
		if !matchPatterns(r, header, size, sig.Patterns) {
			continue
		}

		if sig.Inspect != nil {
			if res, ok := sig.Inspect(r, size); ok {
				return res, nil
			}
		}

		return Result{
			Name:        sig.Name,
			Description: sig.Description,
			Extension:   sig.Extension,
			Aliases:     sig.Aliases,
			MIMEType:    sig.MIMEType,
			Category:    sig.Category,
			Matched:     true,
		}, nil
	}

	if res, ok := detectTextFormat(r, header, size); ok {
		return res, nil
	}

	return UnknownResult(), nil
}

func matchPatterns(r io.ReadSeeker, header []byte, size int64, patterns []Pattern) bool {
	if len(patterns) == 0 {
		return false
	}

	for _, p := range patterns {
		if p.Offset < 0 || len(p.Value) == 0 {
			return false
		}
		end := p.Offset + int64(len(p.Value))
		if end > size {
			return false
		}

		var slice []byte
		if end <= int64(len(header)) {
			slice = header[p.Offset:end]
		} else {
			if _, err := r.Seek(p.Offset, io.SeekStart); err != nil {
				return false
			}
			slice = make([]byte, len(p.Value))
			if _, err := io.ReadFull(r, slice); err != nil {
				return false
			}
		}

		if !bytesMatch(slice, p.Value, p.Mask) {
			return false
		}
	}

	return true
}

func bytesMatch(actual, expected, mask []byte) bool {
	hasMask := len(mask) == len(expected)
	for i := range expected {
		if hasMask {
			if (actual[i] & mask[i]) != (expected[i] & mask[i]) {
				return false
			}
		} else if actual[i] != expected[i] {
			return false
		}
	}
	return true
}
