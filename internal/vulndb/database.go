package vulndb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Database manages local in-memory indices for OSV vulnerabilities and CISA KEV entries.
type Database struct {
	mu           sync.RWMutex
	vulns        []Vulnerability
	vulnsByPURL  map[string][]Vulnerability
	vulnsByName  map[string][]Vulnerability
	kevByCVE     map[string]KEVEntry
	cacheDir     string
	syncChecksum map[string]string
}

// NewDatabase initializes an empty vulnerability database.
func NewDatabase() *Database {
	return &Database{
		vulns:        make([]Vulnerability, 0),
		vulnsByPURL:  make(map[string][]Vulnerability),
		vulnsByName:  make(map[string][]Vulnerability),
		kevByCVE:     make(map[string]KEVEntry),
		syncChecksum: make(map[string]string),
	}
}

// LoadEmbedded loads the pre-compiled offline OSV and KEV fixtures into the database.
func (db *Database) LoadEmbedded() error {
	db.mu.Lock()
	defer db.mu.Unlock()

	// Load OSV
	var osVulns []Vulnerability
	if err := json.Unmarshal([]byte(EmbeddedOSVFixtures), &osVulns); err != nil {
		return fmt.Errorf("failed to unmarshal embedded osv fixtures: %w", err)
	}
	for _, v := range osVulns {
		db.indexVulnerability(v)
	}

	// Load KEV
	var kevCat KEVCatalog
	if err := json.Unmarshal([]byte(EmbeddedKEVFixtures), &kevCat); err != nil {
		return fmt.Errorf("failed to unmarshal embedded kev fixtures: %w", err)
	}
	for _, k := range kevCat.Vulnerabilities {
		db.indexKEV(k)
	}

	return nil
}

// indexVulnerability indexes a single OSV vulnerability into lookup maps. Caller must hold lock.
func (db *Database) indexVulnerability(v Vulnerability) {
	db.vulns = append(db.vulns, v)
	for _, affected := range v.Affected {
		if affected.Package.PURL != "" {
			normalized := strings.ToLower(strings.TrimSpace(affected.Package.PURL))
			db.vulnsByPURL[normalized] = append(db.vulnsByPURL[normalized], v)
		}
		if affected.Package.Name != "" {
			nameKey := strings.ToLower(strings.TrimSpace(affected.Package.Name))
			db.vulnsByName[nameKey] = append(db.vulnsByName[nameKey], v)
			// Also index last segment if contains slash/colon
			if idx := strings.LastIndex(nameKey, "/"); idx != -1 {
				shortName := nameKey[idx+1:]
				db.vulnsByName[shortName] = append(db.vulnsByName[shortName], v)
			}
			if idx := strings.Index(nameKey, ":"); idx != -1 {
				shortName := nameKey[idx+1:]
				db.vulnsByName[shortName] = append(db.vulnsByName[shortName], v)
			}
		}
	}
}

// indexKEV indexes a single KEV catalog record into the lookup map. Caller must hold lock.
func (db *Database) indexKEV(k KEVEntry) {
	cveUpper := strings.ToUpper(strings.TrimSpace(k.CVEID))
	db.kevByCVE[cveUpper] = k
}

// LoadDirectory scans a local cache directory for JSON files and indexes all valid entries.
func (db *Database) LoadDirectory(dir string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	db.cacheDir = dir
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read cache directory %q: %w", dir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		filePath := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}

		// Check if it's KEV catalog
		var kevCat KEVCatalog
		if err := json.Unmarshal(data, &kevCat); err == nil && len(kevCat.Vulnerabilities) > 0 {
			for _, k := range kevCat.Vulnerabilities {
				db.indexKEV(k)
			}
			continue
		}

		// Check if it's OSV list
		var osVulns []Vulnerability
		if err := json.Unmarshal(data, &osVulns); err == nil && len(osVulns) > 0 {
			for _, v := range osVulns {
				db.indexVulnerability(v)
			}
			continue
		}

		// Check if it's single OSV entry
		var singleVuln Vulnerability
		if err := json.Unmarshal(data, &singleVuln); err == nil && singleVuln.ID != "" {
			db.indexVulnerability(singleVuln)
		}
	}

	return nil
}

// QueryByPURL searches for vulnerabilities affecting a given Package URL.
func (db *Database) QueryByPURL(purl string) []Vulnerability {
	db.mu.RLock()
	defer db.mu.RUnlock()

	trimmed := strings.ToLower(strings.TrimSpace(purl))
	// Remove version specifier if present (e.g., pkg:maven/...@1.0.0 -> pkg:maven/...)
	basePURL := trimmed
	if atIdx := strings.Index(trimmed, "@"); atIdx != -1 {
		basePURL = trimmed[:atIdx]
	}

	results, ok := db.vulnsByPURL[basePURL]
	if ok {
		return results
	}
	// Try full PURL exact match
	return db.vulnsByPURL[trimmed]
}

// QueryByPackage searches for vulnerabilities affecting a specific package name.
func (db *Database) QueryByPackage(ecosystem, name string) []Vulnerability {
	db.mu.RLock()
	defer db.mu.RUnlock()

	cleanName := strings.ToLower(strings.TrimSpace(name))
	vulns, ok := db.vulnsByName[cleanName]
	if !ok {
		return nil
	}

	if ecosystem == "" {
		return vulns
	}

	cleanEco := strings.ToLower(strings.TrimSpace(ecosystem))
	var filtered []Vulnerability
	for _, v := range vulns {
		for _, aff := range v.Affected {
			if strings.EqualFold(aff.Package.Ecosystem, cleanEco) {
				filtered = append(filtered, v)
				break
			}
		}
	}
	return filtered
}

// IsKEV checks whether a given CVE identifier or alias exists in the CISA KEV catalog.
func (db *Database) IsKEV(idOrAlias string) (bool, *KEVEntry) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	upper := strings.ToUpper(strings.TrimSpace(idOrAlias))
	if entry, found := db.kevByCVE[upper]; found {
		entryCopy := entry
		return true, &entryCopy
	}
	return false, nil
}

// Counts returns the number of indexed OSV records and KEV records.
func (db *Database) Counts() (int, int) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return len(db.vulns), len(db.kevByCVE)
}

// Sync updates the local cache directory with the latest OSV and KEV catalogs.
// If offline or network errors occur, it gracefully preserves the existing cache or loads embedded fixtures.
func (db *Database) Sync(ctx context.Context, cacheDir string, kevURL string) error {
	if cacheDir == "" {
		cacheDir = ".cra-watchtower/cache"
	}
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory %q: %w", cacheDir, err)
	}

	if kevURL == "" {
		kevURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, kevURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create sync request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		// Network unavailable or offline: save embedded to cache if cache is empty
		_ = db.saveEmbeddedToCache(cacheDir)
		return fmt.Errorf("network sync failed (working offline): %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_ = db.saveEmbeddedToCache(cacheDir)
		return fmt.Errorf("unexpected status from vulnerability feed: %s", resp.Status)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 50*1024*1024))
	if err != nil {
		return fmt.Errorf("failed to read feed response: %w", err)
	}

	var testCat KEVCatalog
	if err := json.Unmarshal(data, &testCat); err != nil {
		return fmt.Errorf("invalid json in synced catalog: %w", err)
	}

	// Calculate SHA-256 integrity checksum
	h := sha256.Sum256(data)
	checksum := hex.EncodeToString(h[:])

	kevFile := filepath.Join(cacheDir, "cisa_kev.json")
	if err := os.WriteFile(kevFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write kev cache: %w", err)
	}

	checksumFile := filepath.Join(cacheDir, "cisa_kev.json.sha256")
	_ = os.WriteFile(checksumFile, []byte(checksum), 0644)

	// Reload database from directory
	return db.LoadDirectory(cacheDir)
}

// saveEmbeddedToCache writes embedded fixtures to cacheDir if files don't already exist.
func (db *Database) saveEmbeddedToCache(cacheDir string) error {
	osvFile := filepath.Join(cacheDir, "osv_embedded.json")
	if _, err := os.Stat(osvFile); errors.Is(err, os.ErrNotExist) {
		_ = os.WriteFile(osvFile, []byte(EmbeddedOSVFixtures), 0644)
	}
	kevFile := filepath.Join(cacheDir, "cisa_kev.json")
	if _, err := os.Stat(kevFile); errors.Is(err, os.ErrNotExist) {
		_ = os.WriteFile(kevFile, []byte(EmbeddedKEVFixtures), 0644)
	}
	return nil
}
