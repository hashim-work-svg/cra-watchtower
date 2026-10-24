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

// ParseBytes parses an SBOM from raw JSON bytes by automatically detecting the format.
func ParseBytes(data []byte) (*SBOM, error) {
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

// ParseReader parses an SBOM from an arbitrary io.Reader.
func ParseReader(r io.Reader) (*SBOM, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read sbom input: %w", err)
	}
	return ParseBytes(data)
}

// ParseFile opens a local filesystem path, reads the content, and parses the SBOM.
func ParseFile(filePath string) (*SBOM, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read sbom file %q: %w", filePath, err)
	}
	return ParseBytes(data)
}
