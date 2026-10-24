// Package diff compares two software bill of materials (SBOMs) to identify
// component modifications, additions, deletions, and delta vulnerability risks.
package diff

import (
	"github.com/hashim-work-svg/cra-watchtower/internal/matcher"
	"github.com/hashim-work-svg/cra-watchtower/internal/sbom"
	"github.com/hashim-work-svg/cra-watchtower/internal/vulndb"
)

// ComponentDelta tracks version changes for a component across SBOMs.
type ComponentDelta struct {
	Name       string `json:"name"`
	PURL       string `json:"purl"`
	OldVersion string `json:"old_version"`
	NewVersion string `json:"new_version"`
}

// DiffResult encapsulates the comparative delta between two SBOMs.
type DiffResult struct {
	OldProduct       string           `json:"old_product"`
	NewProduct       string           `json:"new_product"`
	Added            []sbom.Component `json:"added"`
	Removed          []sbom.Component `json:"removed"`
	Modified         []ComponentDelta `json:"modified"`
	NewFindings      []matcher.Finding `json:"new_findings"`
	ResolvedFindings []matcher.Finding `json:"resolved_findings"`
}

// Compare computes the delta between oldDoc and newDoc.
func Compare(oldDoc, newDoc *sbom.SBOM, db *vulndb.Database) DiffResult {
	result := DiffResult{
		OldProduct:       oldDoc.Metadata.ProductName + " v" + oldDoc.Metadata.ProductVersion,
		NewProduct:       newDoc.Metadata.ProductName + " v" + newDoc.Metadata.ProductVersion,
		Added:            make([]sbom.Component, 0),
		Removed:          make([]sbom.Component, 0),
		Modified:         make([]ComponentDelta, 0),
		NewFindings:      make([]matcher.Finding, 0),
		ResolvedFindings: make([]matcher.Finding, 0),
	}

	oldMap := make(map[string]sbom.Component)
	for _, c := range oldDoc.Components {
		oldMap[c.Name] = c
	}

	newMap := make(map[string]sbom.Component)
	for _, c := range newDoc.Components {
		newMap[c.Name] = c
		if oldComp, exists := oldMap[c.Name]; exists {
			if oldComp.Version != c.Version {
				result.Modified = append(result.Modified, ComponentDelta{
					Name:       c.Name,
					PURL:       c.PURL,
					OldVersion: oldComp.Version,
					NewVersion: c.Version,
				})
			}
		} else {
			result.Added = append(result.Added, c)
		}
	}

	for _, c := range oldDoc.Components {
		if _, exists := newMap[c.Name]; !exists {
			result.Removed = append(result.Removed, c)
		}
	}

	if db != nil {
		oldMatch := matcher.Match(oldDoc, db)
		newMatch := matcher.Match(newDoc, db)

		oldFindingMap := make(map[string]matcher.Finding)
		for _, f := range oldMatch.Findings {
			key := f.Component.Name + ":" + f.CVEID
			oldFindingMap[key] = f
		}

		newFindingMap := make(map[string]matcher.Finding)
		for _, f := range newMatch.Findings {
			key := f.Component.Name + ":" + f.CVEID
			newFindingMap[key] = f
			if _, exists := oldFindingMap[key]; !exists {
				result.NewFindings = append(result.NewFindings, f)
			}
		}

		for _, f := range oldMatch.Findings {
			key := f.Component.Name + ":" + f.CVEID
			if _, exists := newFindingMap[key]; !exists {
				result.ResolvedFindings = append(result.ResolvedFindings, f)
			}
		}
	}

	return result
}
