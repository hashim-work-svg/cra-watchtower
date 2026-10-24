package sbom

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// spdxRaw matches standard SPDX 2.2 / 2.3 JSON structure.
type spdxRaw struct {
	SPDXVersion  string `json:"spdxVersion"`
	Name         string `json:"name"`
	CreationInfo struct {
		Created time.Time `json:"created"`
		Creator []string  `json:"creators"`
	} `json:"creationInfo"`
	Packages []struct {
		Name             string `json:"name"`
		VersionInfo      string `json:"versionInfo"`
		Description      string `json:"description"`
		LicenseConcluded string `json:"licenseConcluded"`
		ExternalRefs     []struct {
			ReferenceCategory string `json:"referenceCategory"`
			ReferenceType     string `json:"referenceType"`
			ReferenceLocator  string `json:"referenceLocator"`
		} `json:"externalRefs"`
		Checksums []struct {
			Algorithm     string `json:"algorithm"`
			ChecksumValue string `json:"checksumValue"`
		} `json:"checksums"`
	} `json:"packages"`
}

// ParseSPDX reads SPDX JSON and transforms it into the normalized SBOM model.
func ParseSPDX(r io.Reader) (*SBOM, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read spdx input: %w", err)
	}

	var raw spdxRaw
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("%w: invalid spdx json: %v", ErrInvalidSBOM, err)
	}

	if !strings.HasPrefix(raw.SPDXVersion, "SPDX-") {
		return nil, fmt.Errorf("%w: missing SPDX- version identifier", ErrInvalidSBOM)
	}

	prodName := raw.Name
	if prodName == "" {
		prodName = "unnamed-spdx-product"
	}

	ts := raw.CreationInfo.Created
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	components := make([]Component, 0, len(raw.Packages))
	for _, p := range raw.Packages {
		if p.Name == "" {
			continue
		}

		var purlStr string
		for _, ref := range p.ExternalRefs {
			if strings.EqualFold(ref.ReferenceType, "purl") {
				purlStr = ref.ReferenceLocator
				break
			}
		}

		purl := EnsurePURL(purlStr, "generic", p.Name, p.VersionInfo)

		var licenses []string
		if p.LicenseConcluded != "" && p.LicenseConcluded != "NOASSERTION" {
			licenses = append(licenses, p.LicenseConcluded)
		}

		var hash string
		if len(p.Checksums) > 0 {
			hash = fmt.Sprintf("%s:%s", p.Checksums[0].Algorithm, p.Checksums[0].ChecksumValue)
		}

		components = append(components, Component{
			Name:        p.Name,
			Version:     p.VersionInfo,
			PURL:        purl,
			Type:        "library",
			Description: p.Description,
			Licenses:    licenses,
			Hash:        hash,
		})
	}

	return &SBOM{
		Format: FormatSPDX,
		Metadata: Metadata{
			ProductName:    prodName,
			ProductVersion: "1.0.0",
			Timestamp:      ts,
			SpecVersion:    raw.SPDXVersion,
		},
		Components: components,
	}, nil
}
