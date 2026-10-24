package drafts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hashim-work-svg/cra-watchtower/internal/clock"
	"github.com/hashim-work-svg/cra-watchtower/internal/matcher"
	"github.com/hashim-work-svg/cra-watchtower/internal/sbom"
	"github.com/hashim-work-svg/cra-watchtower/internal/vulndb"
)

func TestGenerateAndSaveDrafts(t *testing.T) {
	aware := time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC)
	mitigation := aware.Add(48 * time.Hour)
	now := aware.Add(2 * time.Hour)

	tl := clock.CalculateTimeline(aware, &mitigation, now)

	finding := matcher.Finding{
		Component: sbom.Component{
			Name:    "log4j-core",
			Version: "2.14.1",
			PURL:    "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
		},
		VulnerabilityID:              "GHSA-jfh8-c2jp-5v3q",
		CVEID:                        "CVE-2021-44228",
		Summary:                      "Remote code execution in Log4j 2",
		Severity:                     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
		FixedIn:                      "2.15.0",
		IsActivelyExploitedCandidate: true,
		KEVDetails: &vulndb.KEVEntry{
			DateAdded:      "2021-12-10",
			RequiredAction: "Apply vendor updates",
		},
	}

	set := GenerateDrafts(finding, "EdgeGateway-OS", "2.4.0", tl)

	// Validate Early Warning Draft
	if !strings.Contains(set.EarlyWarning, "Article 14(1) Early Warning") {
		t.Errorf("expected Early Warning title")
	}
	if !strings.Contains(set.EarlyWarning, "NOT LEGAL ADVICE") {
		t.Errorf("expected NOT LEGAL ADVICE disclaimer")
	}
	if !strings.Contains(set.EarlyWarning, "CVE-2021-44228") {
		t.Errorf("expected CVE-2021-44228 in technical facts")
	}
	if !strings.Contains(set.EarlyWarning, "[REQUIRED]") {
		t.Errorf("expected [REQUIRED] human action markers")
	}

	// Validate Notification Draft
	if !strings.Contains(set.Notification, "Article 14(2) Vulnerability Notification") {
		t.Errorf("expected Notification title")
	}
	if !strings.Contains(set.Notification, "2.15.0") {
		t.Errorf("expected fixed version in Notification")
	}

	// Validate Final Report Draft
	if !strings.Contains(set.FinalReport, "Article 14(4) Final Report") {
		t.Errorf("expected Final Report title")
	}
	if !strings.Contains(set.FinalReport, "Statutory 14-Day Deadline") {
		t.Errorf("expected 14-day deadline in Final Report")
	}

	// Test SaveDrafts
	tempDir := t.TempDir()
	err := SaveDrafts(set, tempDir, finding.CVEID)
	if err != nil {
		t.Fatalf("failed to save drafts: %v", err)
	}

	f1 := filepath.Join(tempDir, "cve-2021-44228-stage1-early-warning.md")
	f2 := filepath.Join(tempDir, "cve-2021-44228-stage2-notification.md")
	f3 := filepath.Join(tempDir, "cve-2021-44228-stage3-final-report.md")

	for _, f := range []string{f1, f2, f3} {
		info, err := os.Stat(f)
		if err != nil || info.Size() == 0 {
			t.Errorf("expected non-empty draft file at %s, err: %v", f, err)
		}
	}
}
