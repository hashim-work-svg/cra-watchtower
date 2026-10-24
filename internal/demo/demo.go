// Package demo provides a zero-install interactive demonstration of CRA Vulnerability Watchtower
// using embedded sample SBOM fixtures and cached vulnerability databases.
package demo

import (
	_ "embed"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/hashim-work-svg/cra-watchtower/internal/clock"
	"github.com/hashim-work-svg/cra-watchtower/internal/drafts"
	"github.com/hashim-work-svg/cra-watchtower/internal/matcher"
	"github.com/hashim-work-svg/cra-watchtower/internal/report"
	"github.com/hashim-work-svg/cra-watchtower/internal/sbom"
	"github.com/hashim-work-svg/cra-watchtower/internal/vulndb"
)

//go:embed sample_sbom.json
var embeddedSampleSBOM []byte

// Run executes the complete zero-install CRA demonstration.
func Run(w io.Writer) error {
	fmt.Fprintln(w, "================================================================================")
	fmt.Fprintln(w, "  CRA VULNERABILITY WATCHTOWER — ZERO-INSTALL LIVE DEMONSTRATION")
	fmt.Fprintln(w, "  EU Cyber Resilience Act (Regulation EU 2024/2847) Compliance Engine")
	fmt.Fprintln(w, "================================================================================")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[*] DISCLAIMER: NOT LEGAL ADVICE. Technical compliance aid for Article 14.")
	fmt.Fprintln(w)

	// 1. Ingest embedded SBOM
	fmt.Fprintln(w, "[1/5] Ingesting embedded sample SBOM (CycloneDX 1.5 JSON)...")
	doc, err := sbom.ParseBytes(embeddedSampleSBOM)
	if err != nil {
		return fmt.Errorf("demo failed to parse embedded sbom: %w", err)
	}
	fmt.Fprintf(w, "      Product: %s (v%s)\n", doc.Metadata.ProductName, doc.Metadata.ProductVersion)
	fmt.Fprintf(w, "      Components parsed: %d\n", len(doc.Components))
	fmt.Fprintln(w)

	// 2. Load embedded Vulnerability & KEV Database
	fmt.Fprintln(w, "[2/5] Loading offline OSV and CISA KEV vulnerability catalogs...")
	db := vulndb.NewDatabase()
	if err := db.LoadEmbedded(); err != nil {
		return fmt.Errorf("demo failed to load embedded database: %w", err)
	}
	vulnCount, kevCount := db.Counts()
	fmt.Fprintf(w, "      Indexed %d OSV vulnerability advisories and %d CISA KEV records\n", vulnCount, kevCount)
	fmt.Fprintln(w)

	// 3. Correlate and Match
	fmt.Fprintln(w, "[3/5] Correlating components against vulnerability databases & KEV catalog...")
	result := matcher.Match(doc, db)
	fmt.Fprintf(w, "      Identified %d vulnerability findings (%d Actively Exploited Candidates)\n",
		len(result.Findings), result.ExploitedCandidateCount)
	fmt.Fprintln(w)

	// Print Findings Table
	fmt.Fprintf(w, "%-16s %-18s %-10s %-16s %-18s %-12s\n", "CVE / VULN ID", "COMPONENT", "VERSION", "SEVERITY", "KEV EXPLOITED?", "FIXED IN")
	fmt.Fprintf(w, "%-16s %-18s %-10s %-16s %-18s %-12s\n", "-------------", "---------", "-------", "--------", "---------------", "--------")
	for _, f := range result.Findings {
		exploitedTag := "NO"
		if f.IsActivelyExploitedCandidate {
			exploitedTag = "YES (KEV ALERT)"
		}
		fixed := f.FixedIn
		if fixed == "" {
			fixed = "None"
		}
		fmt.Fprintf(w, "%-16s %-18s %-10s %-16s %-18s %-12s\n",
			f.CVEID, truncate(f.Component.Name, 17), f.Component.Version, truncate(f.Severity, 15), exploitedTag, fixed)
	}
	fmt.Fprintln(w)

	// 4. Calculate Article 14 Statutory Reporting Countdown Clocks
	fmt.Fprintln(w, "[4/5] Computing Article 14 statutory countdown deadlines...")
	// Simulate awareness 2 hours ago
	now := time.Now().UTC()
	awarenessTime := now.Add(-2 * time.Hour)
	mitigationTime := now.Add(24 * time.Hour) // Patch estimated in 24 hours
	tl := clock.CalculateTimeline(awarenessTime, &mitigationTime, now)

	fmt.Fprintf(w, "      Awareness Timestamp: %s (Simulated: 2 hours ago)\n", awarenessTime.Format(time.RFC3339))
	fmt.Fprintf(w, "%-35s %-25s %-22s %-10s\n", "REGULATORY STAGE", "STATUTORY DEADLINE (UTC)", "TIME REMAINING", "STATUS")
	fmt.Fprintf(w, "%-35s %-25s %-22s %-10s\n", "----------------", "------------------------", "--------------", "------")
	fmt.Fprintf(w, "%-35s %-25s %-22s %-10s\n",
		tl.EarlyWarning.Stage,
		tl.EarlyWarning.Deadline.Format("2006-01-02 15:04:05 UTC"),
		clock.FormatDuration(tl.EarlyWarning.Remaining),
		tl.EarlyWarning.Status)
	fmt.Fprintf(w, "%-35s %-25s %-22s %-10s\n",
		tl.Notification.Stage,
		tl.Notification.Deadline.Format("2006-01-02 15:04:05 UTC"),
		clock.FormatDuration(tl.Notification.Remaining),
		tl.Notification.Status)
	if tl.FinalReport != nil {
		fmt.Fprintf(w, "%-35s %-25s %-22s %-10s\n",
			tl.FinalReport.Stage,
			tl.FinalReport.Deadline.Format("2006-01-02 15:04:05 UTC"),
			clock.FormatDuration(tl.FinalReport.Remaining),
			tl.FinalReport.Status)
	}
	fmt.Fprintln(w)

	// 5. Generate Article 14 Notification Drafts
	fmt.Fprintln(w, "[5/5] Generating CSIRT/ENISA Article 14 notification drafts...")
	demoDraftsDir := filepath.Join(".", "demo-drafts")
	if len(result.Findings) > 0 {
		topFinding := result.Findings[0]
		draftSet := drafts.GenerateDrafts(topFinding, doc.Metadata.ProductName, doc.Metadata.ProductVersion, tl)
		if err := drafts.SaveDrafts(draftSet, demoDraftsDir, topFinding.CVEID); err != nil {
			return fmt.Errorf("failed to save demo drafts: %w", err)
		}
		fmt.Fprintf(w, "      Saved 3 regulatory notification drafts to %s/:\n", demoDraftsDir)
		fmt.Fprintf(w, "        - %s/cve-2021-44228-stage1-early-warning.md (Early Warning <=24h)\n", demoDraftsDir)
		fmt.Fprintf(w, "        - %s/cve-2021-44228-stage2-notification.md (Notification <=72h)\n", demoDraftsDir)
		fmt.Fprintf(w, "        - %s/cve-2021-44228-stage3-final-report.md (Final Report <=14d)\n", demoDraftsDir)
	}

	// Generate demo HTML dashboard
	demoHTMLPath := filepath.Join(demoDraftsDir, "demo-dashboard.html")
	repData := report.ReportData{
		Result:      *result,
		Timeline:    &tl,
		GeneratedAt: now,
	}
	if err := report.WriteHTMLReport(repData, demoHTMLPath); err == nil {
		fmt.Fprintf(w, "        - %s (Interactive HTML Dashboard)\n", demoHTMLPath)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "================================================================================")
	fmt.Fprintln(w, "  DEMO COMPLETE: All Article 14 checks executed offline with zero network calls.")
	fmt.Fprintln(w, "================================================================================")
	return nil
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max-3] + "..."
	}
	return s
}
