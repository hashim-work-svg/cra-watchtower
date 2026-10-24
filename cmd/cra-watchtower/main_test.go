package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestCLIIntegration(t *testing.T) {
	cyclonedxPath := filepath.Join("..", "..", "fixtures", "sample-cyclonedx.json")
	spdxPath := filepath.Join("..", "..", "fixtures", "sample-spdx.json")

	if _, err := os.Stat(cyclonedxPath); err != nil {
		t.Fatalf("sample-cyclonedx fixture missing: %v", err)
	}

	t.Run("Verify loadDatabase", func(t *testing.T) {
		db := loadDatabase("")
		vCount, kCount := db.Counts()
		if vCount == 0 || kCount == 0 {
			t.Errorf("expected non-zero embedded counts, got v=%d, k=%d", vCount, kCount)
		}
	})

	t.Run("Verify truncate helper", func(t *testing.T) {
		s := truncate("very long string here that should be truncated", 10)
		if len(s) != 10 || s != "very lo..." {
			t.Errorf("unexpected truncate result: %q", s)
		}
		short := truncate("short", 10)
		if short != "short" {
			t.Errorf("expected short unchanged, got %q", short)
		}
	})

	t.Run("Subcommand: version", func(t *testing.T) {
		cmd := newRootCmd()
		cmd.SetArgs([]string{"version"})
		var buf bytes.Buffer
		cmd.SetOut(&buf)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("version failed: %v", err)
		}
	})

	t.Run("Subcommand: ingest CycloneDX and SPDX", func(t *testing.T) {
		cmd1 := newRootCmd()
		cmd1.SetArgs([]string{"ingest", cyclonedxPath})
		if err := cmd1.Execute(); err != nil {
			t.Errorf("ingest cyclonedx failed: %v", err)
		}

		cmd2 := newRootCmd()
		cmd2.SetArgs([]string{"ingest", spdxPath, "--json"})
		if err := cmd2.Execute(); err != nil {
			t.Errorf("ingest spdx json failed: %v", err)
		}
	})

	t.Run("Subcommand: match", func(t *testing.T) {
		cmd1 := newRootCmd()
		cmd1.SetArgs([]string{"match", cyclonedxPath})
		if err := cmd1.Execute(); err != nil {
			t.Errorf("match failed: %v", err)
		}

		cmd2 := newRootCmd()
		cmd2.SetArgs([]string{"match", cyclonedxPath, "--json"})
		if err := cmd2.Execute(); err != nil {
			t.Errorf("match json failed: %v", err)
		}
	})

	t.Run("Subcommand: clock", func(t *testing.T) {
		cmd1 := newRootCmd()
		cmd1.SetArgs([]string{"clock", "--aware", "2026-10-24T10:00:00Z"})
		if err := cmd1.Execute(); err != nil {
			t.Errorf("clock failed: %v", err)
		}

		cmd2 := newRootCmd()
		cmd2.SetArgs([]string{"clock", "--aware", "2026-10-24T10:00:00Z", "--mitigated", "2026-10-25T12:00:00Z", "--json"})
		if err := cmd2.Execute(); err != nil {
			t.Errorf("clock with mitigation failed: %v", err)
		}
	})

	t.Run("Subcommand: drafts", func(t *testing.T) {
		tempDir := t.TempDir()
		cmd := newRootCmd()
		cmd.SetArgs([]string{"drafts", cyclonedxPath, "--cve", "CVE-2021-44228", "--aware", "2026-10-24T10:00:00Z", "-o", tempDir})
		if err := cmd.Execute(); err != nil {
			t.Errorf("drafts failed: %v", err)
		}
	})

	t.Run("Subcommand: report", func(t *testing.T) {
		tempDir := t.TempDir()
		outHTML := filepath.Join(tempDir, "out.html")
		cmd1 := newRootCmd()
		cmd1.SetArgs([]string{"report", cyclonedxPath, "-o", outHTML, "--aware", "2026-10-24T10:00:00Z"})
		if err := cmd1.Execute(); err != nil {
			t.Errorf("report html failed: %v", err)
		}

		cmd2 := newRootCmd()
		cmd2.SetArgs([]string{"report", cyclonedxPath, "--md"})
		if err := cmd2.Execute(); err != nil {
			t.Errorf("report md failed: %v", err)
		}
	})

	t.Run("Subcommand: diff", func(t *testing.T) {
		cmd := newRootCmd()
		cmd.SetArgs([]string{"diff", cyclonedxPath, cyclonedxPath, "--json"})
		if err := cmd.Execute(); err != nil {
			t.Errorf("diff failed: %v", err)
		}
	})

	t.Run("Subcommand: demo", func(t *testing.T) {
		cmd := newRootCmd()
		cmd.SetArgs([]string{"demo"})
		if err := cmd.Execute(); err != nil {
			t.Errorf("demo failed: %v", err)
		}
		_ = os.RemoveAll("demo-drafts")
	})
}
