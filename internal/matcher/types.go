// Package matcher correlates software bill of materials (SBOM) components with
// vulnerability databases and flags actively exploited candidates.
package matcher

import (
	"time"

	"github.com/hashim-work-svg/cra-watchtower/internal/sbom"
	"github.com/hashim-work-svg/cra-watchtower/internal/vulndb"
)

// Finding represents a single identified vulnerability impacting an ingested component.
type Finding struct {
	Component                   sbom.Component   `json:"component"`
	VulnerabilityID             string           `json:"vulnerability_id"`
	CVEID                       string           `json:"cve_id"`
	Summary                     string           `json:"summary"`
	Details                     string           `json:"details"`
	Severity                    string           `json:"severity"`
	FixedIn                     string           `json:"fixed_in,omitempty"`
	IsActivelyExploitedCandidate bool             `json:"is_actively_exploited_candidate"`
	KEVDetails                  *vulndb.KEVEntry `json:"kev_details,omitempty"`
	References                  []string         `json:"references,omitempty"`
}

// MatchResult aggregates all findings for a product SBOM.
type MatchResult struct {
	ProductName             string    `json:"product_name"`
	ProductVersion          string    `json:"product_version"`
	Timestamp               time.Time `json:"timestamp"`
	TotalComponents         int       `json:"total_components"`
	Findings                []Finding `json:"findings"`
	ExploitedCandidateCount int       `json:"exploited_candidate_count"`
}

// HasExploitedCandidates returns true if any finding is an actively exploited candidate.
func (r *MatchResult) HasExploitedCandidates() bool {
	return r.ExploitedCandidateCount > 0
}

// GetFindingByCVE looks up a specific finding by CVE or vulnerability identifier.
func (r *MatchResult) GetFindingByCVE(cveID string) *Finding {
	for i := range r.Findings {
		f := &r.Findings[i]
		if f.CVEID == cveID || f.VulnerabilityID == cveID {
			return f
		}
	}
	return nil
}
