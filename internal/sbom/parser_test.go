package sbom

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestParseCycloneDX(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "fixtures", "sample-cyclonedx.json")
	sbomDoc, err := ParseFile(fixturePath)
	if err != nil {
		t.Fatalf("failed to parse cyclonedx fixture: %v", err)
	}

	if sbomDoc.Format != FormatCycloneDX {
		t.Errorf("expected format %s, got %s", FormatCycloneDX, sbomDoc.Format)
	}

	if sbomDoc.Metadata.ProductName != "EdgeGateway-OS" {
		t.Errorf("expected product name 'EdgeGateway-OS', got %q", sbomDoc.Metadata.ProductName)
	}

	if sbomDoc.Metadata.ProductVersion != "2.4.0" {
		t.Errorf("expected product version '2.4.0', got %q", sbomDoc.Metadata.ProductVersion)
	}

	if len(sbomDoc.Components) != 4 {
		t.Fatalf("expected 4 components, got %d", len(sbomDoc.Components))
	}

	// Verify log4j component
	c0 := sbomDoc.Components[0]
	if c0.Name != "log4j-core" {
		t.Errorf("expected first component 'log4j-core', got %q", c0.Name)
	}
	if c0.PURL != "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" {
		t.Errorf("unexpected purl: %s", c0.PURL)
	}
	if len(c0.Licenses) != 1 || c0.Licenses[0] != "Apache-2.0" {
		t.Errorf("unexpected licenses: %v", c0.Licenses)
	}
}

func TestParseSPDX(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "fixtures", "sample-spdx.json")
	sbomDoc, err := ParseFile(fixturePath)
	if err != nil {
		t.Fatalf("failed to parse spdx fixture: %v", err)
	}

	if sbomDoc.Format != FormatSPDX {
		t.Errorf("expected format %s, got %s", FormatSPDX, sbomDoc.Format)
	}

	if sbomDoc.Metadata.ProductName != "CloudAgent-Daemon" {
		t.Errorf("expected product name 'CloudAgent-Daemon', got %q", sbomDoc.Metadata.ProductName)
	}

	if len(sbomDoc.Components) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(sbomDoc.Components))
	}

	c0 := sbomDoc.Components[0]
	if c0.Name != "openssl" {
		t.Errorf("expected first component 'openssl', got %q", c0.Name)
	}
	if c0.Version != "1.1.1k" {
		t.Errorf("expected version 1.1.1k, got %q", c0.Version)
	}
	if c0.PURL != "pkg:generic/openssl@1.1.1k" {
		t.Errorf("unexpected purl: %s", c0.PURL)
	}
}

func TestParseMalformed(t *testing.T) {
	t.Run("Non-SBOM JSON", func(t *testing.T) {
		fixturePath := filepath.Join("..", "..", "fixtures", "malformed.json")
		_, err := ParseFile(fixturePath)
		if err == nil {
			t.Fatal("expected error parsing non-sbom JSON, got nil")
		}
		if !errors.Is(err, ErrUnsupportedFormat) {
			t.Errorf("expected ErrUnsupportedFormat, got: %v", err)
		}
	})

	t.Run("Syntax Error", func(t *testing.T) {
		brokenJSON := []byte(`{"bomFormat": "CycloneDX", broken`)
		_, err := ParseBytes(brokenJSON)
		if err == nil {
			t.Fatal("expected error parsing broken JSON syntax, got nil")
		}
	})

	t.Run("Non-existent File", func(t *testing.T) {
		_, err := ParseFile("non_existent_file.json")
		if err == nil {
			t.Fatal("expected error for non-existent file, got nil")
		}
	})

	t.Run("ParseReader Success and Failure", func(t *testing.T) {
		validJSON := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","metadata":{"component":{"name":"TestApp","version":"1.0.0"}}}`)
		doc, err := ParseBytes(validJSON)
		if err != nil {
			t.Fatalf("unexpected error parsing valid bytes: %v", err)
		}
		if doc.Metadata.ProductName != "TestApp" {
			t.Errorf("expected TestApp, got %s", doc.Metadata.ProductName)
		}
	})
}
