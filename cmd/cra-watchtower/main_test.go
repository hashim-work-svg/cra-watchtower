package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCLIIntegration(t *testing.T) {
	cyclonedxPath := filepath.Join("..", "..", "fixtures", "sample-cyclonedx.json")
	spdxPath := filepath.Join("..", "..", "fixtures", "sample-spdx.json")

	// Ensure sample fixtures exist
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

	t.Run("Verify SPDX fixture exists", func(t *testing.T) {
		if _, err := os.Stat(spdxPath); err != nil {
			t.Errorf("sample-spdx fixture missing: %v", err)
		}
	})
}
