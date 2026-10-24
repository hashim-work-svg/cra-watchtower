package vulndb

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestDatabaseLoadEmbedded(t *testing.T) {
	db := NewDatabase()
	if err := db.LoadEmbedded(); err != nil {
		t.Fatalf("failed to load embedded fixtures: %v", err)
	}

	vulnCount, kevCount := db.Counts()
	if vulnCount < 3 {
		t.Errorf("expected at least 3 vulnerabilities, got %d", vulnCount)
	}
	if kevCount < 2 {
		t.Errorf("expected at least 2 KEV entries, got %d", kevCount)
	}

	// Test QueryByPURL
	vulns := db.QueryByPURL("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
	if len(vulns) == 0 {
		t.Fatalf("expected to find vulnerabilities for log4j-core PURL")
	}
	if vulns[0].ID != "GHSA-jfh8-c2jp-5v3q" {
		t.Errorf("expected GHSA-jfh8-c2jp-5v3q, got %s", vulns[0].ID)
	}

	// Test QueryByPackage
	pkgVulns := db.QueryByPackage("Maven", "log4j-core")
	if len(pkgVulns) == 0 {
		t.Fatalf("expected to find package vulnerabilities for log4j-core")
	}

	// Test QueryByPackage with ecosystem filter mismatch
	mismatch := db.QueryByPackage("npm", "log4j-core")
	if len(mismatch) != 0 {
		t.Errorf("expected 0 matches for npm log4j-core, got %d", len(mismatch))
	}

	// Test IsKEV
	isKEV, entry := db.IsKEV("CVE-2021-44228")
	if !isKEV || entry == nil {
		t.Fatalf("expected CVE-2021-44228 to be in KEV catalog")
	}
	if entry.VendorProject != "Apache" {
		t.Errorf("expected VendorProject Apache, got %q", entry.VendorProject)
	}

	// Test non-KEV
	isNonKEV, _ := db.IsKEV("CVE-9999-9999")
	if isNonKEV {
		t.Errorf("expected CVE-9999-9999 to NOT be in KEV catalog")
	}
}

func TestDatabaseLoadDirectory(t *testing.T) {
	tempDir := t.TempDir()

	customOSV := `[
		{
			"id": "CUSTOM-VULN-001",
			"summary": "Custom Test Vulnerability",
			"affected": [
				{
					"package": {
						"ecosystem": "npm",
						"name": "custom-pkg",
						"purl": "pkg:npm/custom-pkg"
					}
				}
			]
		}
	]`
	if err := os.WriteFile(filepath.Join(tempDir, "custom.json"), []byte(customOSV), 0644); err != nil {
		t.Fatalf("failed to write custom json: %v", err)
	}

	db := NewDatabase()
	if err := db.LoadDirectory(tempDir); err != nil {
		t.Fatalf("failed to load directory: %v", err)
	}

	vulns := db.QueryByPURL("pkg:npm/custom-pkg@1.0.0")
	if len(vulns) != 1 {
		t.Fatalf("expected 1 match from loaded directory, got %d", len(vulns))
	}
	if vulns[0].ID != "CUSTOM-VULN-001" {
		t.Errorf("expected CUSTOM-VULN-001, got %s", vulns[0].ID)
	}
}

func TestDatabaseSync(t *testing.T) {
	// Mock HTTP server
	mockKEV := `{
		"title": "Mock KEV Catalog",
		"catalogVersion": "2026.10.24",
		"dateReleased": "2026-10-24T00:00:00Z",
		"count": 1,
		"vulnerabilities": [
			{
				"cveID": "CVE-2026-12345",
				"vendorProject": "MockVendor",
				"product": "MockProduct",
				"vulnerabilityName": "Mock Vuln",
				"dateAdded": "2026-10-24",
				"shortDescription": "Mock description",
				"requiredAction": "Patch it",
				"dueDate": "2026-11-01"
			}
		]
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(mockKEV))
	}))
	defer server.Close()

	tempDir := t.TempDir()
	db := NewDatabase()

	ctx := context.Background()
	err := db.Sync(ctx, tempDir, server.URL)
	if err != nil {
		t.Fatalf("expected successful sync, got: %v", err)
	}

	isKEV, entry := db.IsKEV("CVE-2026-12345")
	if !isKEV || entry == nil {
		t.Fatalf("expected synced CVE-2026-12345 to be in KEV catalog")
	}

	// Verify checksum file was written
	checksumPath := filepath.Join(tempDir, "cisa_kev.json.sha256")
	data, err := os.ReadFile(checksumPath)
	if err != nil || len(data) != 64 {
		t.Errorf("expected 64-character sha256 checksum file, got err: %v, len: %d", err, len(data))
	}
}

func TestDatabaseSyncFailure(t *testing.T) {
	tempDir := t.TempDir()
	db := NewDatabase()

	// Connect to non-existent server to simulate offline / network error
	ctx := context.Background()
	err := db.Sync(ctx, tempDir, "http://127.0.0.1:54321/nonexistent")
	if err == nil {
		t.Fatal("expected error on network failure, got nil")
	}

	// Verify embedded fallback was saved to cache
	cachedKEV := filepath.Join(tempDir, "cisa_kev.json")
	if _, err := os.Stat(cachedKEV); os.IsNotExist(err) {
		t.Errorf("expected fallback cisa_kev.json to be created in cache on offline run")
	}
}
