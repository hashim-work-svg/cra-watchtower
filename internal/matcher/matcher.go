package matcher

import (
	"strconv"
	"strings"
	"time"

	"github.com/hashim-work-svg/cra-watchtower/internal/sbom"
	"github.com/hashim-work-svg/cra-watchtower/internal/vulndb"
)

// Match scans components in the provided SBOM against the vulnerability database
// and identifies affected versions and actively exploited candidates.
func Match(doc *sbom.SBOM, db *vulndb.Database) *MatchResult {
	result := &MatchResult{
		ProductName:     doc.Metadata.ProductName,
		ProductVersion:  doc.Metadata.ProductVersion,
		Timestamp:       time.Now().UTC(),
		TotalComponents: len(doc.Components),
		Findings:        make([]Finding, 0),
	}

	seenFinding := make(map[string]bool)

	for _, comp := range doc.Components {
		// 1. Query by PURL
		vulns := db.QueryByPURL(comp.PURL)
		// 2. Also query by package name if no PURL match
		if len(vulns) == 0 {
			vulns = db.QueryByPackage(comp.Type, comp.Name)
		}

		for _, v := range vulns {
			isAffected, fixedIn := checkVersionAffected(comp.Version, v.Affected)
			if !isAffected {
				continue
			}

			key := comp.PURL + ":" + v.ID
			if seenFinding[key] {
				continue
			}
			seenFinding[key] = true

			cveID := extractCVE(v)
			isKEV, kevDetails := db.IsKEV(cveID)
			if !isKEV {
				// Check aliases
				for _, alias := range v.Aliases {
					if strings.HasPrefix(strings.ToUpper(alias), "CVE-") {
						if matched, details := db.IsKEV(alias); matched {
							isKEV = true
							kevDetails = details
							cveID = alias
							break
						}
					}
				}
			}

			var refs []string
			for _, ref := range v.References {
				refs = append(refs, ref.URL)
			}

			severityScore := "UNKNOWN"
			if len(v.Severity) > 0 {
				severityScore = v.Severity[0].Score
			}

			finding := Finding{
				Component:                    comp,
				VulnerabilityID:              v.ID,
				CVEID:                        cveID,
				Summary:                      v.Summary,
				Details:                      v.Details,
				Severity:                     severityScore,
				FixedIn:                      fixedIn,
				IsActivelyExploitedCandidate: isKEV,
				KEVDetails:                   kevDetails,
				References:                   refs,
			}

			if isKEV {
				result.ExploitedCandidateCount++
			}
			result.Findings = append(result.Findings, finding)
		}
	}

	return result
}

// extractCVE returns the CVE identifier if present in aliases or ID.
func extractCVE(v vulndb.Vulnerability) string {
	if strings.HasPrefix(strings.ToUpper(v.ID), "CVE-") {
		return strings.ToUpper(v.ID)
	}
	for _, alias := range v.Aliases {
		if strings.HasPrefix(strings.ToUpper(alias), "CVE-") {
			return strings.ToUpper(alias)
		}
	}
	return v.ID
}

// checkVersionAffected verifies if compVersion falls within the affected range.
// Returns (isAffected, fixedIn).
func checkVersionAffected(compVersion string, affectedList []vulndb.AffectedPackage) (bool, string) {
	cleanComp := strings.TrimSpace(strings.TrimPrefix(compVersion, "v"))
	if cleanComp == "" {
		return false, ""
	}

	for _, aff := range affectedList {
		// 1. Check explicit versions list
		for _, v := range aff.Versions {
			cleanV := strings.TrimSpace(strings.TrimPrefix(v, "v"))
			if cleanComp == cleanV {
				// Affected by explicit list
				fixedIn := extractFixedVersion(aff.Ranges)
				return true, fixedIn
			}
		}

		// 2. Check ranges
		for _, r := range aff.Ranges {
			var introduced, fixed string
			for _, ev := range r.Events {
				if ev.Introduced != "" {
					introduced = strings.TrimSpace(strings.TrimPrefix(ev.Introduced, "v"))
				}
				if ev.Fixed != "" {
					fixed = strings.TrimSpace(strings.TrimPrefix(ev.Fixed, "v"))
				}
			}

			// If fixed is explicitly equal to compVersion, it is not affected!
			if fixed != "" && compareVersions(cleanComp, fixed) >= 0 {
				continue
			}

			// If introduced is empty or compVersion >= introduced
			if introduced == "" || introduced == "0" || compareVersions(cleanComp, introduced) >= 0 {
				return true, fixed
			}
		}
	}

	return false, ""
}

// extractFixedVersion extracts the first fixed version from ranges.
func extractFixedVersion(ranges []vulndb.Range) string {
	for _, r := range ranges {
		for _, ev := range r.Events {
			if ev.Fixed != "" {
				return ev.Fixed
			}
		}
	}
	return ""
}

// compareVersions returns -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2.
// Supports dotted semver formats (e.g. 2.14.1 vs 2.15.0).
func compareVersions(v1, v2 string) int {
	if v1 == v2 {
		return 0
	}

	p1 := strings.Split(v1, ".")
	p2 := strings.Split(v2, ".")

	maxLen := len(p1)
	if len(p2) > maxLen {
		maxLen = len(p2)
	}

	for i := 0; i < maxLen; i++ {
		var n1, n2 int
		if i < len(p1) {
			n1, _ = strconv.Atoi(cleanNumeric(p1[i]))
		}
		if i < len(p2) {
			n2, _ = strconv.Atoi(cleanNumeric(p2[i]))
		}

		if n1 < n2 {
			return -1
		}
		if n1 > n2 {
			return 1
		}
	}

	return 0
}

func cleanNumeric(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			sb.WriteRune(r)
		} else {
			break
		}
	}
	return sb.String()
}
