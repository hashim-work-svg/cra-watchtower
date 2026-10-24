package matcher

import (
	"testing"

	"github.com/hashim-work-svg/cra-watchtower/internal/sbom"
	"github.com/hashim-work-svg/cra-watchtower/internal/vulndb"
)

func TestMatcherWithEmbeddedDatabase(t *testing.T) {
	db := vulndb.NewDatabase()
	if err := db.LoadEmbedded(); err != nil {
		t.Fatalf("failed to load embedded database: %v", err)
	}

	testCases := []struct {
		name                 string
		components           []sbom.Component
		expectedFindings     int
		expectedExploited    int
		checkFindingCVE      string
		expectFindingMatched bool
	}{
		{
			name: "Vulnerable Log4j2 component matches and flags KEV",
			components: []sbom.Component{
				{
					Name:    "log4j-core",
					Version: "2.14.1",
					Type:    "library",
					PURL:    "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
				},
			},
			expectedFindings:     1,
			expectedExploited:    1,
			checkFindingCVE:      "CVE-2021-44228",
			expectFindingMatched: true,
		},
		{
			name: "Fixed Log4j2 version (2.16.0) does NOT match vulnerability",
			components: []sbom.Component{
				{
					Name:    "log4j-core",
					Version: "2.16.0",
					Type:    "library",
					PURL:    "pkg:maven/org.apache.logging.log4j/log4j-core@2.16.0",
				},
			},
			expectedFindings:     0,
			expectedExploited:    0,
			checkFindingCVE:      "CVE-2021-44228",
			expectFindingMatched: false,
		},
		{
			name: "Commons Text vulnerable 1.9 matches",
			components: []sbom.Component{
				{
					Name:    "commons-text",
					Version: "1.9",
					Type:    "library",
					PURL:    "pkg:maven/org.apache.commons/commons-text@1.9",
				},
			},
			expectedFindings:     1,
			expectedExploited:    1,
			checkFindingCVE:      "CVE-2022-42889",
			expectFindingMatched: true,
		},
		{
			name: "Commons Text fixed 1.10.0 does NOT match",
			components: []sbom.Component{
				{
					Name:    "commons-text",
					Version: "1.10.0",
					Type:    "library",
					PURL:    "pkg:maven/org.apache.commons/commons-text@1.10.0",
				},
			},
			expectedFindings:     0,
			expectedExploited:    0,
			checkFindingCVE:      "CVE-2022-42889",
			expectFindingMatched: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			doc := &sbom.SBOM{
				Metadata: sbom.Metadata{
					ProductName:    "TestApp",
					ProductVersion: "1.0.0",
				},
				Components: tc.components,
			}

			result := Match(doc, db)
			if len(result.Findings) != tc.expectedFindings {
				t.Fatalf("expected %d findings, got %d", tc.expectedFindings, len(result.Findings))
			}
			if result.ExploitedCandidateCount != tc.expectedExploited {
				t.Errorf("expected %d exploited candidates, got %d", tc.expectedExploited, result.ExploitedCandidateCount)
			}

			f := result.GetFindingByCVE(tc.checkFindingCVE)
			if tc.expectFindingMatched {
				if f == nil {
					t.Fatalf("expected finding for %s, got nil", tc.checkFindingCVE)
				}
				if !f.IsActivelyExploitedCandidate {
					t.Errorf("expected finding %s to be marked as actively exploited candidate", tc.checkFindingCVE)
				}
				if f.KEVDetails == nil {
					t.Errorf("expected KEV details to be populated for %s", tc.checkFindingCVE)
				}
			} else {
				if f != nil {
					t.Errorf("expected no finding for %s, got %#v", tc.checkFindingCVE, f)
				}
			}
		})
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		v1       string
		v2       string
		expected int
	}{
		{"2.14.1", "2.15.0", -1},
		{"2.15.0", "2.14.1", 1},
		{"1.0.0", "1.0.0", 0},
		{"1.5", "1.10.0", -1},
		{"1.10.0", "1.9", 1},
	}

	for _, tc := range tests {
		got := compareVersions(tc.v1, tc.v2)
		if got != tc.expected {
			t.Errorf("compareVersions(%q, %q) = %d, expected %d", tc.v1, tc.v2, got, tc.expected)
		}
	}
}
