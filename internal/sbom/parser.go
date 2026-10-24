package sbom

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// DetectFormat inspects raw JSON byte content and determines if it is CycloneDX or SPDX.
func DetectFormat(data []byte) FormatType {
	var probe struct {
		BOMFormat   string `json:"bomFormat"`
		SPDXVersion string `json:"spdxVersion"`
	}

	if err := json.Unmarshal(data, &probe); err != nil {
		return FormatUnknown
	}

	if strings.EqualFold(probe.BOMFormat, "CycloneDX") {
		return FormatCycloneDX
	}

	if strings.HasPrefix(strings.ToUpper(probe.SPDXVersion), "SPDX-") {
		return FormatSPDX
	}

	return FormatUnknown
}

const (
	// MaxSBOMSizeBytes is the maximum allowed size for an SBOM input (10 MB).
	MaxSBOMSizeBytes = 10 * 1024 * 1024
)

// ErrSBOMTooLarge is returned when the SBOM input exceeds MaxSBOMSizeBytes.
var ErrSBOMTooLarge = fmt.Errorf("sbom file exceeds maximum allowed size of %d bytes", MaxSBOMSizeBytes)

// ParseBytes parses an SBOM from raw JSON bytes by automatically detecting the format.
func ParseBytes(data []byte) (*SBOM, error) {
	if len(data) > MaxSBOMSizeBytes {
		return nil, ErrSBOMTooLarge
	}
	format := DetectFormat(data)
	reader := bytes.NewReader(data)

	switch format {
	case FormatCycloneDX:
		return ParseCycloneDX(reader)
	case FormatSPDX:
		return ParseSPDX(reader)
	default:
		return nil, fmt.Errorf("%w: unrecognized format or non-SBOM JSON", ErrUnsupportedFormat)
	}
}

// ParseReader parses an SBOM from an arbitrary io.Reader with a bounded size limit.
func ParseReader(r io.Reader) (*SBOM, error) {
	limitedReader := io.LimitReader(r, MaxSBOMSizeBytes+1)
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read sbom input: %w", err)
	}
	if len(data) > MaxSBOMSizeBytes {
		return nil, ErrSBOMTooLarge
	}
	return ParseBytes(data)
}

// ParseFile opens a local filesystem path, reads the content up to MaxSBOMSizeBytes, and parses the SBOM.
func ParseFile(filePath string) (*SBOM, error) {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat sbom file %q: %w", filePath, err)
	}
	if fileInfo.Size() > MaxSBOMSizeBytes {
		return nil, fmt.Errorf("%w: %s (%d bytes)", ErrSBOMTooLarge, filePath, fileInfo.Size())
	}

	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sbom file %q: %w", filePath, err)
	}
	defer f.Close()

	return ParseReader(f)
}
