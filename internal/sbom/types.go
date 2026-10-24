// Package sbom provides software bill of materials (SBOM) parsing, normalization,
// and Package URL (PURL) resolution for CycloneDX and SPDX standards.
package sbom

import (
	"fmt"
	"time"
)

// FormatType indicates the SBOM serialization specification.
type FormatType string

const (
	// FormatCycloneDX denotes a CycloneDX specification SBOM.
	FormatCycloneDX FormatType = "CycloneDX"
	// FormatSPDX denotes an SPDX specification SBOM.
	FormatSPDX FormatType = "SPDX"
	// FormatUnknown denotes an unrecognized specification format.
	FormatUnknown FormatType = "Unknown"
)

// Component represents a single normalized software package or dependency.
type Component struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	PURL        string   `json:"purl"`
	Type        string   `json:"type"`
	Supplier    string   `json:"supplier,omitempty"`
	Licenses    []string `json:"licenses,omitempty"`
	Description string   `json:"description,omitempty"`
	Hash        string   `json:"hash,omitempty"`
}

// Metadata holds metadata about the target product described by the SBOM.
type Metadata struct {
	ProductName    string    `json:"product_name"`
	ProductVersion string    `json:"product_version"`
	Timestamp      time.Time `json:"timestamp"`
	SpecVersion    string    `json:"spec_version"`
	Manufacturer   string    `json:"manufacturer,omitempty"`
}

// SBOM is the unified, normalized software bill of materials representation.
type SBOM struct {
	Format     FormatType  `json:"format"`
	Metadata   Metadata    `json:"metadata"`
	Components []Component `json:"components"`
}

// ErrInvalidSBOM is returned when an SBOM file is malformed or lacks required fields.
var ErrInvalidSBOM = fmt.Errorf("invalid sbom")

// ErrUnsupportedFormat is returned when the SBOM format cannot be determined.
var ErrUnsupportedFormat = fmt.Errorf("unsupported sbom format")
