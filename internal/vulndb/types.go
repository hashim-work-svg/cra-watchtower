// Package vulndb provides vulnerability database models and query capabilities
// for OSV (Open Source Vulnerability) and CISA KEV (Known Exploited Vulnerabilities) catalogs.
package vulndb

import "time"

// Vulnerability represents an OSV-compliant vulnerability entry.
type Vulnerability struct {
	ID         string            `json:"id"`
	Summary    string            `json:"summary"`
	Details    string            `json:"details"`
	Aliases    []string          `json:"aliases,omitempty"`
	Modified   time.Time         `json:"modified,omitempty"`
	Published  time.Time         `json:"published,omitempty"`
	Severity   []Severity        `json:"severity,omitempty"`
	Affected   []AffectedPackage `json:"affected"`
	References []Reference       `json:"references,omitempty"`
}

// Severity represents CVSS or scoring details.
type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// AffectedPackage defines the package and version ranges affected by a vulnerability.
type AffectedPackage struct {
	Package           PackageMetadata `json:"package"`
	Ranges            []Range         `json:"ranges,omitempty"`
	Versions          []string        `json:"versions,omitempty"`
	DatabaseSpecific  map[string]any  `json:"database_specific,omitempty"`
	EcosystemSpecific map[string]any  `json:"ecosystem_specific,omitempty"`
}

// PackageMetadata holds ecosystem and package identification.
type PackageMetadata struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	PURL      string `json:"purl,omitempty"`
}

// Range specifies version ranges (SEMVER, ECOSYSTEM, GIT) and events (introduced, fixed, last_affected).
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

// Event denotes version boundary markers.
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

// Reference holds external URLs (advisories, patches, reports).
type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// KEVEntry represents an entry in the CISA Known Exploited Vulnerabilities (KEV) catalog.
type KEVEntry struct {
	CVEID                      string `json:"cveID"`
	VendorProject              string `json:"vendorProject"`
	Product                    string `json:"product"`
	VulnerabilityName          string `json:"vulnerabilityName"`
	DateAdded                  string `json:"dateAdded"`
	ShortDescription           string `json:"shortDescription"`
	RequiredAction             string `json:"requiredAction"`
	DueDate                    string `json:"dueDate"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse,omitempty"`
	Notes                      string `json:"notes,omitempty"`
}

// KEVCatalog represents the top-level CISA KEV JSON catalog structure.
type KEVCatalog struct {
	Title           string     `json:"title"`
	CatalogVersion  string     `json:"catalogVersion"`
	DateReleased    string     `json:"dateReleased"`
	Count           int        `json:"count"`
	Vulnerabilities []KEVEntry `json:"vulnerabilities"`
}
