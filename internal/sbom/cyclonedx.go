package sbom

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// cycloneDXRaw matches the core JSON structure of CycloneDX SBOMs.
type cycloneDXRaw struct {
	BOMFormat   string `json:"bomFormat"`
	SpecVersion string `json:"specVersion"`
	Metadata    struct {
		Timestamp time.Time `json:"timestamp"`
		Component struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Type    string `json:"type"`
		} `json:"component"`
		Manufacture struct {
			Name string `json:"name"`
		} `json:"manufacture"`
	} `json:"metadata"`
	Components []struct {
		Name        string `json:"name"`
		Version     string `json:"version"`
		PURL        string `json:"purl"`
		Type        string `json:"type"`
		Description string `json:"description"`
		Licenses    []struct {
			License struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"license"`
		} `json:"licenses"`
		Hashes []struct {
			Alg     string `json:"alg"`
			Content string `json:"content"`
		} `json:"hashes"`
	} `json:"components"`
}

// ParseCycloneDX reads CycloneDX JSON and transforms it into the normalized SBOM model.
func ParseCycloneDX(r io.Reader) (*SBOM, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read cyclonedx input: %w", err)
	}

	var raw cycloneDXRaw
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("%w: invalid cyclonedx json: %v", ErrInvalidSBOM, err)
	}

	if raw.BOMFormat != "CycloneDX" && raw.SpecVersion == "" {
		return nil, fmt.Errorf("%w: missing CycloneDX header", ErrInvalidSBOM)
	}

	prodName := raw.Metadata.Component.Name
	if prodName == "" {
		prodName = "unnamed-product"
	}

	prodVersion := raw.Metadata.Component.Version
	if prodVersion == "" {
		prodVersion = "0.0.0"
	}

	ts := raw.Metadata.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	components := make([]Component, 0, len(raw.Components))
	for _, c := range raw.Components {
		if c.Name == "" {
			continue
		}

		purl := EnsurePURL(c.PURL, c.Type, c.Name, c.Version)

		var licenses []string
		for _, lic := range c.Licenses {
			if lic.License.ID != "" {
				licenses = append(licenses, lic.License.ID)
			} else if lic.License.Name != "" {
				licenses = append(licenses, lic.License.Name)
			}
		}

		var hash string
		if len(c.Hashes) > 0 {
			hash = fmt.Sprintf("%s:%s", c.Hashes[0].Alg, c.Hashes[0].Content)
		}

		components = append(components, Component{
			Name:        c.Name,
			Version:     c.Version,
			PURL:        purl,
			Type:        c.Type,
			Description: c.Description,
			Licenses:    licenses,
			Hash:        hash,
		})
	}

	return &SBOM{
		Format: FormatCycloneDX,
		Metadata: Metadata{
			ProductName:    prodName,
			ProductVersion: prodVersion,
			Timestamp:      ts,
			SpecVersion:    raw.SpecVersion,
			Manufacturer:   raw.Metadata.Manufacture.Name,
		},
		Components: components,
	}, nil
}
