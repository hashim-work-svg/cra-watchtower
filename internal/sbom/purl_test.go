package sbom

import (
	"testing"
)

func TestNormalizePURL(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    string
		expectError bool
	}{
		{
			name:        "Valid lowercase npm",
			input:       "pkg:npm/express@4.17.1",
			expected:    "pkg:npm/express@4.17.1",
			expectError: false,
		},
		{
			name:        "Uppercase type canonicalization",
			input:       "pkg:GOLANG/github.com/gin-gonic/gin@v1.9.0",
			expected:    "pkg:golang/github.com/gin-gonic/gin@v1.9.0",
			expectError: false,
		},
		{
			name:        "Maven with namespace",
			input:       "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
			expected:    "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
			expectError: false,
		},
		{
			name:        "Empty string error",
			input:       "",
			expected:    "",
			expectError: true,
		},
		{
			name:        "Invalid scheme error",
			input:       "http://not-a-purl.com",
			expected:    "",
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizePURL(tc.input)
			if tc.expectError {
				if err == nil {
					t.Fatalf("expected error for %q, got nil", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.input, err)
			}
			if got != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}

func TestEnsurePURL(t *testing.T) {
	tests := []struct {
		name         string
		existingPURL string
		compType     string
		compName     string
		version      string
		expected     string
	}{
		{
			name:         "Keep valid purl",
			existingPURL: "pkg:npm/lodash@4.17.21",
			compType:     "npm",
			compName:     "lodash",
			version:      "4.17.21",
			expected:     "pkg:npm/lodash@4.17.21",
		},
		{
			name:         "Fallback for missing purl with python type",
			existingPURL: "",
			compType:     "python",
			compName:     "requests",
			version:      "2.28.1",
			expected:     "pkg:pypi/requests@2.28.1",
		},
		{
			name:         "Fallback for unknown type",
			existingPURL: "",
			compType:     "custom",
			compName:     "internal-lib",
			version:      "1.0.0",
			expected:     "pkg:generic/internal-lib@1.0.0",
		},
		{
			name:         "Fallback with empty name",
			existingPURL: "",
			compType:     "golang",
			compName:     "",
			version:      "1.0.0",
			expected:     "pkg:golang/unknown-component@1.0.0",
		},
		{
			name:         "Ecosystem mappings",
			existingPURL: "",
			compType:     "cargo",
			compName:     "serde",
			version:      "1.0",
			expected:     "pkg:cargo/serde@1.0",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := EnsurePURL(tc.existingPURL, tc.compType, tc.compName, tc.version)
			if got != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}

func TestParsePURL(t *testing.T) {
	t.Run("Valid PURL", func(t *testing.T) {
		purl, err := ParsePURL("pkg:golang/github.com/gin-gonic/gin@v1.9.0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if purl.Type != "golang" || purl.Name != "gin" {
			t.Errorf("unexpected parsed purl: %#v", purl)
		}
	})

	t.Run("Invalid PURL", func(t *testing.T) {
		_, err := ParsePURL("invalid purl")
		if err == nil {
			t.Fatal("expected error parsing invalid purl, got nil")
		}
	})
}
