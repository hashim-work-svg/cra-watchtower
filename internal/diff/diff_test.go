package diff

import (
	"testing"

	"github.com/hashim-work-svg/cra-watchtower/internal/sbom"
	"github.com/hashim-work-svg/cra-watchtower/internal/vulndb"
)

func TestCompare(t *testing.T) {
	db := vulndb.NewDatabase()
	if err := db.LoadEmbedded(); err != nil {
		t.Fatalf("failed to load embedded vulndb: %v", err)
	}

	oldDoc := &sbom.SBOM{
		Metadata: sbom.Metadata{
			ProductName:    "App",
			ProductVersion: "1.0.0",
		},
		Components: []sbom.Component{
			{Name: "log4j-core", Version: "2.14.1", PURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
			{Name: "old-lib", Version: "1.0.0", PURL: "pkg:generic/old-lib@1.0.0"},
		},
	}

	newDoc := &sbom.SBOM{
		Metadata: sbom.Metadata{
			ProductName:    "App",
			ProductVersion: "1.1.0",
		},
		Components: []sbom.Component{
			// Upgraded to non-vulnerable version
			{Name: "log4j-core", Version: "2.16.0", PURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.16.0"},
			// Added new component
			{Name: "new-lib", Version: "2.0.0", PURL: "pkg:generic/new-lib@2.0.0"},
		},
	}

	diffResult := Compare(oldDoc, newDoc, db)

	if len(diffResult.Added) != 1 || diffResult.Added[0].Name != "new-lib" {
		t.Errorf("expected new-lib in Added, got %#v", diffResult.Added)
	}

	if len(diffResult.Removed) != 1 || diffResult.Removed[0].Name != "old-lib" {
		t.Errorf("expected old-lib in Removed, got %#v", diffResult.Removed)
	}

	if len(diffResult.Modified) != 1 || diffResult.Modified[0].Name != "log4j-core" {
		t.Errorf("expected log4j-core in Modified, got %#v", diffResult.Modified)
	}
	if diffResult.Modified[0].OldVersion != "2.14.1" || diffResult.Modified[0].NewVersion != "2.16.0" {
		t.Errorf("expected version change 2.14.1 -> 2.16.0")
	}

	if len(diffResult.ResolvedFindings) != 1 || diffResult.ResolvedFindings[0].CVEID != "CVE-2021-44228" {
		t.Errorf("expected resolved finding for CVE-2021-44228, got %#v", diffResult.ResolvedFindings)
	}
}
