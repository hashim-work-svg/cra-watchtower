// Package main is the entry point for the cra-watchtower CLI.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hashim-work-svg/cra-watchtower/internal/clock"
	"github.com/hashim-work-svg/cra-watchtower/internal/demo"
	"github.com/hashim-work-svg/cra-watchtower/internal/diff"
	"github.com/hashim-work-svg/cra-watchtower/internal/drafts"
	"github.com/hashim-work-svg/cra-watchtower/internal/matcher"
	"github.com/hashim-work-svg/cra-watchtower/internal/report"
	"github.com/hashim-work-svg/cra-watchtower/internal/sbom"
	"github.com/hashim-work-svg/cra-watchtower/internal/vulndb"
	"github.com/spf13/cobra"
)

var (
	// Version is injected during build time via ldflags.
	Version = "v0.1.0-dev"
	// Commit is injected during build time via ldflags.
	Commit = "none"
	// Date is injected during build time via ldflags.
	Date = "unknown"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "cra-watchtower",
		Short: "EU Cyber Resilience Act (CRA) Vulnerability & Compliance Engine",
		Long: `cra-watchtower ingests CycloneDX and SPDX SBOMs, normalizes dependencies to
Package URLs (PURL), correlates them against vulnerability databases (OSV) and actively
exploited catalogs (CISA KEV), tracks Article 14 statutory countdowns (24h early warning,
72h notification, 14d final report), and generates official CSIRT/ENISA notification drafts.

NOTICE: Technical compliance aid only. Not legal advice.`,
	}

	// 1. version
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print binary version and build metadata",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("cra-watchtower %s (commit: %s, date: %s)\n", Version, Commit, Date)
		},
	}

	// 2. ingest
	var jsonIngest bool
	ingestCmd := &cobra.Command{
		Use:   "ingest [sbom-file]",
		Short: "Ingest and normalize a CycloneDX or SPDX SBOM file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			filePath := args[0]
			doc, err := sbom.ParseFile(filePath)
			if err != nil {
				return fmt.Errorf("failed to parse sbom: %w", err)
			}

			if jsonIngest {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(doc)
			}

			fmt.Printf("Successfully ingested %s SBOM:\n", doc.Format)
			fmt.Printf("  Product: %s (v%s)\n", doc.Metadata.ProductName, doc.Metadata.ProductVersion)
			fmt.Printf("  Timestamp: %s\n", doc.Metadata.Timestamp.Format("2006-01-02 15:04:05 UTC"))
			fmt.Printf("  Components Ingested: %d\n\n", len(doc.Components))

			fmt.Printf("%-30s %-12s %-45s\n", "NAME", "VERSION", "PURL")
			fmt.Printf("%-30s %-12s %-45s\n", "----", "-------", "----")
			for _, c := range doc.Components {
				fmt.Printf("%-30s %-12s %-45s\n", truncate(c.Name, 28), truncate(c.Version, 10), c.PURL)
			}
			return nil
		},
	}
	ingestCmd.Flags().BoolVar(&jsonIngest, "json", false, "Output normalized SBOM as JSON")

	// 3. sync
	var syncCacheDir string
	syncCmd := &cobra.Command{
		Use:   "sync",
		Short: "Download and update local vulnerability and KEV catalogs",
		RunE: func(cmd *cobra.Command, args []string) error {
			db := vulndb.NewDatabase()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			fmt.Println("[*] Synchronizing CISA KEV and OSV catalogs...")
			err := db.Sync(ctx, syncCacheDir, "")
			if err != nil {
				fmt.Printf("[!] Warning: %v\n", err)
				fmt.Println("[*] Falling back to embedded offline fixtures.")
				_ = db.LoadEmbedded()
			}
			vCount, kCount := db.Counts()
			fmt.Printf("[+] Cache updated at %s: %d vulnerabilities, %d KEV entries indexed.\n", syncCacheDir, vCount, kCount)
			return nil
		},
	}
	syncCmd.Flags().StringVar(&syncCacheDir, "cache-dir", ".cra-watchtower/cache", "Path to local vulnerability cache directory")

	// 4. match
	var (
		matchCacheDir string
		jsonMatch     bool
		failOnExploit bool
	)
	matchCmd := &cobra.Command{
		Use:   "match [sbom-file]",
		Short: "Find vulnerabilities and actively exploited candidates in an SBOM",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			doc, err := sbom.ParseFile(args[0])
			if err != nil {
				return fmt.Errorf("failed to parse sbom: %w", err)
			}

			db := loadDatabase(matchCacheDir)
			result := matcher.Match(doc, db)

			if jsonMatch {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(result)
			}

			fmt.Printf("Vulnerability Matching Results for %s (v%s):\n", result.ProductName, result.ProductVersion)
			fmt.Printf("  Components Scanned: %d\n", result.TotalComponents)
			fmt.Printf("  Findings: %d (%d Actively Exploited Candidates)\n\n",
				len(result.Findings), result.ExploitedCandidateCount)

			if len(result.Findings) == 0 {
				fmt.Println("No known vulnerabilities identified.")
				return nil
			}

			fmt.Fprintf(os.Stdout, "%-16s %-18s %-10s %-16s %-18s %-12s\n", "CVE / VULN ID", "COMPONENT", "VERSION", "SEVERITY", "KEV EXPLOITED?", "FIXED IN")
			fmt.Fprintf(os.Stdout, "%-16s %-18s %-10s %-16s %-18s %-12s\n", "-------------", "---------", "-------", "--------", "---------------", "--------")
			for _, f := range result.Findings {
				exploitedTag := "NO"
				if f.IsActivelyExploitedCandidate {
					exploitedTag = "YES (KEV ALERT)"
				}
				fixed := f.FixedIn
				if fixed == "" {
					fixed = "None"
				}
				fmt.Fprintf(os.Stdout, "%-16s %-18s %-10s %-16s %-18s %-12s\n",
					f.CVEID, truncate(f.Component.Name, 17), f.Component.Version, truncate(f.Severity, 15), exploitedTag, fixed)
			}

			if failOnExploit && result.ExploitedCandidateCount > 0 {
				fmt.Printf("\n[!] CI Gate Failed: %d actively exploited vulnerability candidate(s) detected.\n", result.ExploitedCandidateCount)
				os.Exit(2)
			}
			return nil
		},
	}
	matchCmd.Flags().StringVar(&matchCacheDir, "cache-dir", ".cra-watchtower/cache", "Path to local vulnerability cache directory")
	matchCmd.Flags().BoolVar(&jsonMatch, "json", false, "Output results as JSON")
	matchCmd.Flags().BoolVar(&failOnExploit, "fail-on-exploited", false, "Exit with code 2 if any actively exploited candidate is detected")

	// 5. clock
	var (
		awareStr     string
		mitigatedStr string
		jsonClock    bool
	)
	clockCmd := &cobra.Command{
		Use:   "clock",
		Short: "Calculate Article 14 statutory countdown deadlines and compliance status",
		RunE: func(cmd *cobra.Command, args []string) error {
			if awareStr == "" {
				return fmt.Errorf("--aware timestamp is required (RFC3339 format, e.g. 2026-10-24T10:00:00Z)")
			}

			awareTime, err := time.Parse(time.RFC3339, awareStr)
			if err != nil {
				return fmt.Errorf("invalid --aware timestamp: %w", err)
			}

			var mitTime *time.Time
			if mitigatedStr != "" {
				t, err := time.Parse(time.RFC3339, mitigatedStr)
				if err != nil {
					return fmt.Errorf("invalid --mitigated timestamp: %w", err)
				}
				mitTime = &t
			}

			tl := clock.CalculateTimeline(awareTime, mitTime, time.Now().UTC())

			if jsonClock {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(tl)
			}

			fmt.Println("EU Cyber Resilience Act (Article 14) Reporting Clock:")
			fmt.Printf("  Awareness Time: %s\n", tl.AwarenessTime.Format(time.RFC3339))
			if tl.MitigationTime != nil {
				fmt.Printf("  Mitigation Time: %s\n", tl.MitigationTime.Format(time.RFC3339))
			} else {
				fmt.Println("  Mitigation Time: Pending availability")
			}
			fmt.Println()

			fmt.Fprintf(os.Stdout, "%-35s %-25s %-22s %-10s\n", "REGULATORY STAGE", "STATUTORY DEADLINE (UTC)", "TIME REMAINING", "STATUS")
			fmt.Fprintf(os.Stdout, "%-35s %-25s %-22s %-10s\n", "----------------", "------------------------", "--------------", "------")
			fmt.Fprintf(os.Stdout, "%-35s %-25s %-22s %-10s\n",
				tl.EarlyWarning.Stage,
				tl.EarlyWarning.Deadline.Format("2006-01-02 15:04:05 UTC"),
				clock.FormatDuration(tl.EarlyWarning.Remaining),
				tl.EarlyWarning.Status)
			fmt.Fprintf(os.Stdout, "%-35s %-25s %-22s %-10s\n",
				tl.Notification.Stage,
				tl.Notification.Deadline.Format("2006-01-02 15:04:05 UTC"),
				clock.FormatDuration(tl.Notification.Remaining),
				tl.Notification.Status)
			if tl.FinalReport != nil {
				fmt.Fprintf(os.Stdout, "%-35s %-25s %-22s %-10s\n",
					tl.FinalReport.Stage,
					tl.FinalReport.Deadline.Format("2006-01-02 15:04:05 UTC"),
					clock.FormatDuration(tl.FinalReport.Remaining),
					tl.FinalReport.Status)
			}
			return nil
		},
	}
	clockCmd.Flags().StringVar(&awareStr, "aware", "", "Timestamp when manufacturer became aware of vulnerability (RFC3339)")
	clockCmd.Flags().StringVar(&mitigatedStr, "mitigated", "", "Timestamp when corrective or mitigating measure became available (RFC3339)")
	clockCmd.Flags().BoolVar(&jsonClock, "json", false, "Output timeline as JSON")

	// 6. drafts
	var (
		draftsCVE          string
		draftsAwareStr     string
		draftsMitigatedStr string
		draftsOutputDir    string
		draftsCacheDir     string
	)
	draftsCmd := &cobra.Command{
		Use:   "drafts [sbom-file]",
		Short: "Generate Article 14 notification drafts for CSIRTs and ENISA",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if draftsAwareStr == "" {
				draftsAwareStr = time.Now().UTC().Format(time.RFC3339)
			}
			awareTime, err := time.Parse(time.RFC3339, draftsAwareStr)
			if err != nil {
				return fmt.Errorf("invalid --aware timestamp: %w", err)
			}

			var mitTime *time.Time
			if draftsMitigatedStr != "" {
				t, err := time.Parse(time.RFC3339, draftsMitigatedStr)
				if err != nil {
					return fmt.Errorf("invalid --mitigated timestamp: %w", err)
				}
				mitTime = &t
			}

			doc, err := sbom.ParseFile(args[0])
			if err != nil {
				return fmt.Errorf("failed to parse sbom: %w", err)
			}

			db := loadDatabase(draftsCacheDir)
			res := matcher.Match(doc, db)

			var targetFinding *matcher.Finding
			if draftsCVE != "" {
				targetFinding = res.GetFindingByCVE(draftsCVE)
			} else if len(res.Findings) > 0 {
				targetFinding = &res.Findings[0]
			}

			if targetFinding == nil {
				return fmt.Errorf("no matching finding found for CVE %q", draftsCVE)
			}

			tl := clock.CalculateTimeline(awareTime, mitTime, time.Now().UTC())
			set := drafts.GenerateDrafts(*targetFinding, doc.Metadata.ProductName, doc.Metadata.ProductVersion, tl)

			if draftsOutputDir == "" {
				draftsOutputDir = "drafts"
			}
			if err := drafts.SaveDrafts(set, draftsOutputDir, targetFinding.CVEID); err != nil {
				return fmt.Errorf("failed to save drafts: %w", err)
			}

			fmt.Printf("Generated 3 Article 14 notification drafts in %s/ for %s:\n", draftsOutputDir, targetFinding.CVEID)
			fmt.Printf("  - Stage 1: %s/%s-stage1-early-warning.md (<=24h)\n", draftsOutputDir, strings.ToLower(targetFinding.CVEID))
			fmt.Printf("  - Stage 2: %s/%s-stage2-notification.md (<=72h)\n", draftsOutputDir, strings.ToLower(targetFinding.CVEID))
			fmt.Printf("  - Stage 3: %s/%s-stage3-final-report.md (<=14d after mitigation)\n", draftsOutputDir, strings.ToLower(targetFinding.CVEID))
			return nil
		},
	}
	draftsCmd.Flags().StringVar(&draftsCVE, "cve", "", "Target CVE identifier (defaults to first finding)")
	draftsCmd.Flags().StringVar(&draftsAwareStr, "aware", "", "Awareness timestamp (RFC3339, defaults to now)")
	draftsCmd.Flags().StringVar(&draftsMitigatedStr, "mitigated", "", "Mitigation available timestamp (RFC3339)")
	draftsCmd.Flags().StringVarP(&draftsOutputDir, "output-dir", "o", "drafts", "Directory to write drafts")
	draftsCmd.Flags().StringVar(&draftsCacheDir, "cache-dir", ".cra-watchtower/cache", "Cache directory")

	// 7. report
	var (
		reportOutput   string
		reportAwareStr string
		reportCacheDir string
		markdownReport bool
	)
	reportCmd := &cobra.Command{
		Use:   "report [sbom-file]",
		Short: "Generate standalone HTML compliance dashboard or Markdown report",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			doc, err := sbom.ParseFile(args[0])
			if err != nil {
				return fmt.Errorf("failed to parse sbom: %w", err)
			}

			db := loadDatabase(reportCacheDir)
			res := matcher.Match(doc, db)

			var tl *clock.Timeline
			if reportAwareStr != "" {
				awareTime, err := time.Parse(time.RFC3339, reportAwareStr)
				if err == nil {
					t := clock.CalculateTimeline(awareTime, nil, time.Now().UTC())
					tl = &t
				}
			}

			data := report.ReportData{
				Result:      *res,
				Timeline:    tl,
				GeneratedAt: time.Now().UTC(),
			}

			if markdownReport {
				md := report.GenerateMarkdown(data)
				if reportOutput != "" {
					return os.WriteFile(reportOutput, []byte(md), 0644)
				}
				fmt.Println(md)
				return nil
			}

			if reportOutput == "" {
				reportOutput = "cra-report.html"
			}
			if err := report.WriteHTMLReport(data, reportOutput); err != nil {
				return fmt.Errorf("failed to write html report: %w", err)
			}
			fmt.Printf("Successfully generated compliance dashboard: %s\n", reportOutput)
			return nil
		},
	}
	reportCmd.Flags().StringVarP(&reportOutput, "output", "o", "", "Destination file path (.html or .md)")
	reportCmd.Flags().StringVar(&reportAwareStr, "aware", "", "Awareness timestamp (RFC3339)")
	reportCmd.Flags().StringVar(&reportCacheDir, "cache-dir", ".cra-watchtower/cache", "Cache directory")
	reportCmd.Flags().BoolVar(&markdownReport, "md", false, "Generate Markdown summary instead of HTML")

	// 8. diff
	var (
		diffCacheDir string
		jsonDiff     bool
	)
	diffCmd := &cobra.Command{
		Use:   "diff [old-sbom] [new-sbom]",
		Short: "Compare two SBOM versions and identify delta component & vulnerability changes",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			oldDoc, err := sbom.ParseFile(args[0])
			if err != nil {
				return fmt.Errorf("failed to parse old sbom: %w", err)
			}
			newDoc, err := sbom.ParseFile(args[1])
			if err != nil {
				return fmt.Errorf("failed to parse new sbom: %w", err)
			}

			db := loadDatabase(diffCacheDir)
			res := diff.Compare(oldDoc, newDoc, db)

			if jsonDiff {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(res)
			}

			fmt.Printf("SBOM Differential: %s -> %s\n", res.OldProduct, res.NewProduct)
			fmt.Printf("  Added Components:    %d\n", len(res.Added))
			fmt.Printf("  Removed Components:  %d\n", len(res.Removed))
			fmt.Printf("  Modified Components: %d\n", len(res.Modified))
			fmt.Printf("  New Vulnerabilities: %d\n", len(res.NewFindings))
			fmt.Printf("  Resolved Findings:   %d\n\n", len(res.ResolvedFindings))

			if len(res.Modified) > 0 {
				fmt.Println("Component Version Changes:")
				for _, m := range res.Modified {
					fmt.Printf("  * %s: %s -> %s\n", m.Name, m.OldVersion, m.NewVersion)
				}
				fmt.Println()
			}

			if len(res.NewFindings) > 0 {
				fmt.Println("New Vulnerabilities Detected:")
				for _, nf := range res.NewFindings {
					fmt.Printf("  ! [%s] %s in %s (v%s)\n", nf.CVEID, nf.Summary, nf.Component.Name, nf.Component.Version)
				}
				fmt.Println()
			}
			return nil
		},
	}
	diffCmd.Flags().StringVar(&diffCacheDir, "cache-dir", ".cra-watchtower/cache", "Cache directory")
	diffCmd.Flags().BoolVar(&jsonDiff, "json", false, "Output diff as JSON")

	// 9. demo
	demoCmd := &cobra.Command{
		Use:   "demo",
		Short: "Run live zero-install demonstration with embedded fixtures",
		RunE: func(cmd *cobra.Command, args []string) error {
			return demo.Run(os.Stdout)
		},
	}

	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(ingestCmd)
	rootCmd.AddCommand(syncCmd)
	rootCmd.AddCommand(matchCmd)
	rootCmd.AddCommand(clockCmd)
	rootCmd.AddCommand(draftsCmd)
	rootCmd.AddCommand(reportCmd)
	rootCmd.AddCommand(diffCmd)
	rootCmd.AddCommand(demoCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// loadDatabase initializes a database from cacheDir if available, falling back to embedded fixtures.
func loadDatabase(cacheDir string) *vulndb.Database {
	db := vulndb.NewDatabase()
	if cacheDir != "" {
		_ = db.LoadDirectory(cacheDir)
	}
	// Also ensure embedded fixtures are loaded
	_ = db.LoadEmbedded()
	return db
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max-3] + "..."
	}
	return s
}
