package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hashim-work-svg/cra-watchtower/internal/clock"
	"github.com/hashim-work-svg/cra-watchtower/internal/matcher"
	"github.com/hashim-work-svg/cra-watchtower/internal/sbom"
)

func TestReportGeneration(t *testing.T) {
	aware := time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC)
	mitigation := aware.Add(24 * time.Hour)
	now := aware.Add(2 * time.Hour)

	tl := clock.CalculateTimeline(aware, &mitigation, now)

	data := ReportData{
		Result: matcher.MatchResult{
			ProductName:             "EdgeGateway-OS",
			ProductVersion:          "2.4.0",
			Timestamp:               now,
			TotalComponents:         4,
			ExploitedCandidateCount: 1,
			Findings: []matcher.Finding{
				{
					Component: sbom.Component{
						Name:    "log4j-core",
						Version: "2.14.1",
						PURL:    "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
					},
					CVEID:                        "CVE-2021-44228",
					VulnerabilityID:              "GHSA-jfh8-c2jp-5v3q",
					Severity:                     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
					FixedIn:                      "2.15.0",
					IsActivelyExploitedCandidate: true,
				},
			},
		},
		Timeline:    &tl,
		GeneratedAt: now,
	}

	t.Run("Generate HTML Report", func(t *testing.T) {
		html, err := GenerateHTML(data)
		if err != nil {
			t.Fatalf("failed to generate html report: %v", err)
		}

		if !strings.Contains(html, "EdgeGateway-OS") {
			t.Errorf("expected product name in html")
		}
		if !strings.Contains(html, "CVE-2021-44228") {
			t.Errorf("expected CVE in html")
		}
		if !strings.Contains(html, "KEV EXPLOITED") {
			t.Errorf("expected KEV EXPLOITED badge in html")
		}
		if !strings.Contains(html, "DISCLAIMER: NOT LEGAL ADVICE") {
			t.Errorf("expected legal disclaimer in html")
		}
		if !strings.Contains(html, "Stage 1: Early Warning") {
			t.Errorf("expected Early Warning in html table")
		}
	})

	t.Run("Generate Markdown Report", func(t *testing.T) {
		md := GenerateMarkdown(data)
		if !strings.Contains(md, "# CRA Compliance Scan Summary: EdgeGateway-OS") {
			t.Errorf("expected markdown header")
		}
		if !strings.Contains(md, "CVE-2021-44228") {
			t.Errorf("expected CVE in markdown")
		}
		if !strings.Contains(md, "**YES (KEV)**") {
			t.Errorf("expected KEV tag in markdown")
		}
	})

	t.Run("Write HTML Report to Disk", func(t *testing.T) {
		tempDir := t.TempDir()
		outPath := filepath.Join(tempDir, "report.html")

		err := WriteHTMLReport(data, outPath)
		if err != nil {
			t.Fatalf("failed to write html report: %v", err)
		}

		info, err := os.Stat(outPath)
		if err != nil || info.Size() == 0 {
			t.Errorf("expected non-empty html file on disk, err: %v", err)
		}
	})

	t.Run("Empty Findings Report", func(t *testing.T) {
		emptyData := ReportData{
			Result: matcher.MatchResult{
				ProductName:    "CleanApp",
				ProductVersion: "1.0.0",
			},
			GeneratedAt: now,
		}

		html, err := GenerateHTML(emptyData)
		if err != nil {
			t.Fatalf("unexpected error for empty findings: %v", err)
		}
		if !strings.Contains(html, "No known vulnerabilities identified") {
			t.Errorf("expected clean message in html")
		}

		md := GenerateMarkdown(emptyData)
		if !strings.Contains(md, "No vulnerabilities identified") {
			t.Errorf("expected clean message in markdown")
		}
	})
}
