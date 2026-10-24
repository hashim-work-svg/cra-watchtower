package sbom

import (
	"fmt"
	"strings"

	"github.com/package-url/packageurl-go"
)

// NormalizePURL parses and canonicalizes a Package URL string according to the purl-spec.
// If the input is invalid or empty, it returns an error.
func NormalizePURL(rawPURL string) (string, error) {
	trimmed := strings.TrimSpace(rawPURL)
	if trimmed == "" {
		return "", fmt.Errorf("purl cannot be empty")
	}

	instance, err := packageurl.FromString(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid purl syntax: %w", err)
	}

	// Canonicalize: lowercase type
	instance.Type = strings.ToLower(instance.Type)

	return instance.ToString(), nil
}

// EnsurePURL guarantees that a component has a valid canonical PURL.
// If existing PURL is valid, it normalizes it. If missing, it constructs a canonical fallback.
func EnsurePURL(existingPURL, compType, name, version string) string {
	if existingPURL != "" {
		if normalized, err := NormalizePURL(existingPURL); err == nil {
			return normalized
		}
	}

	cleanName := strings.TrimSpace(name)
	cleanVersion := strings.TrimSpace(version)
	if cleanName == "" {
		cleanName = "unknown-component"
	}

	purlType := mapComponentTypeToPURLType(compType)
	var namespace string

	// Handle Maven groupId:artifactId syntax
	if strings.Contains(cleanName, ":") {
		parts := strings.SplitN(cleanName, ":", 2)
		namespace = parts[0]
		cleanName = parts[1]
		if purlType == packageurl.TypeGeneric {
			purlType = packageurl.TypeMaven
		}
	} else if strings.HasPrefix(cleanName, "@") && strings.Contains(cleanName, "/") {
		// NPM scoped package e.g. @angular/core
		parts := strings.SplitN(cleanName, "/", 2)
		namespace = parts[0]
		cleanName = parts[1]
		if purlType == packageurl.TypeGeneric {
			purlType = packageurl.TypeNPM
		}
	} else if (strings.HasPrefix(cleanName, "github.com/") || strings.HasPrefix(cleanName, "golang.org/")) && strings.Contains(cleanName, "/") {
		// Go module path e.g. github.com/gin-gonic/gin
		idx := strings.LastIndex(cleanName, "/")
		namespace = cleanName[:idx]
		cleanName = cleanName[idx+1:]
		if purlType == packageurl.TypeGeneric {
			purlType = packageurl.TypeGolang
		}
	}

	instance := packageurl.NewPackageURL(purlType, namespace, cleanName, cleanVersion, nil, "")
	return instance.ToString()
}

// mapComponentTypeToPURLType maps generic component strings to PackageURL types.
func mapComponentTypeToPURLType(compType string) string {
	lower := strings.ToLower(strings.TrimSpace(compType))
	switch lower {
	case "golang", "go":
		return packageurl.TypeGolang
	case "npm", "javascript", "nodejs":
		return packageurl.TypeNPM
	case "pypi", "python":
		return packageurl.TypePyPi
	case "maven", "java":
		return packageurl.TypeMaven
	case "nuget", "dotnet", "csharp":
		return packageurl.TypeNuget
	case "cargo", "rust":
		return packageurl.TypeCargo
	case "gem", "ruby":
		return packageurl.TypeGem
	case "deb", "debian":
		return packageurl.TypeDebian
	case "rpm":
		return packageurl.TypeRPM
	default:
		return packageurl.TypeGeneric
	}
}

// ParsePURL breaks a valid PURL into its constituent parts for vulnerability queries.
func ParsePURL(purlString string) (*packageurl.PackageURL, error) {
	instance, err := packageurl.FromString(strings.TrimSpace(purlString))
	if err != nil {
		return nil, fmt.Errorf("failed to parse purl: %w", err)
	}
	return &instance, nil
}
