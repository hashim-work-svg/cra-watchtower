// Package main is the entry point for the cra-watchtower CLI.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/hashim-work-svg/cra-watchtower/internal/sbom"
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
		Short: "CRA Vulnerability Watchtower: EU Cyber Resilience Act Compliance Engine",
		Long: `CRA Vulnerability Watchtower monitors software dependencies against public
vulnerability databases (OSV) and actively exploited catalogs (CISA KEV) to enforce
and automate EU Cyber Resilience Act (Regulation EU 2024/2847) early-warning
and reporting obligations (24-hour, 72-hour, and 14-day windows).`,
	}

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print binary version and build metadata",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("cra-watchtower %s (commit: %s, date: %s)\n", Version, Commit, Date)
		},
	}

	var jsonOutput bool
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

			if jsonOutput {
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
				fmt.Printf("%-30s %-12s %-45s\n", truncateString(c.Name, 28), truncateString(c.Version, 10), c.PURL)
			}
			return nil
		},
	}
	ingestCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output normalized SBOM as JSON")

	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(ingestCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func truncateString(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen-3] + "..."
	}
	return s
}
