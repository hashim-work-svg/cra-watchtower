package demo

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestRunDemo(t *testing.T) {
	var buf bytes.Buffer
	err := Run(&buf)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}

	out := buf.String()

	// Verify key outputs
	if !strings.Contains(out, "CRA VULNERABILITY WATCHTOWER") {
		t.Errorf("expected header in demo output")
	}
	if !strings.Contains(out, "DISCLAIMER: NOT LEGAL ADVICE") {
		t.Errorf("expected disclaimer in demo output")
	}
	if !strings.Contains(out, "EdgeGateway-OS") {
		t.Errorf("expected product EdgeGateway-OS in demo output")
	}
	if !strings.Contains(out, "CVE-2021-44228") {
		t.Errorf("expected CVE-2021-44228 in findings")
	}
	if !strings.Contains(out, "YES (KEV ALERT)") {
		t.Errorf("expected KEV ALERT in findings")
	}
	if !strings.Contains(out, "Stage 1: Early Warning") {
		t.Errorf("expected Stage 1 deadline in demo output")
	}
	if !strings.Contains(out, "DEMO COMPLETE") {
		t.Errorf("expected DEMO COMPLETE in output")
	}

	// Clean up created demo-drafts directory
	_ = os.RemoveAll("demo-drafts")
}
