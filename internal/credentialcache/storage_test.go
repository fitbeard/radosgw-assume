package credentialcache

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fitbeard/radosgw-assume/internal/config"
)

func TestStoreRefreshesUnusableEntries(t *testing.T) {
	now := time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		cached *config.AssumeRoleResult
	}{
		{name: "expired", cached: testResult(now.Add(-time.Second))},
		{name: "inside safety margin", cached: testResult(now.Add(refreshWindow(time.Hour)))},
		{name: "malformed expiration", cached: testResult(now)},
		{name: "missing credentials", cached: testResult(now.Add(time.Hour))},
	}
	tests[2].cached.Expiration = "tomorrow"
	tests[3].cached.SecretAccessKey = ""

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			store := newStore(directory, func() time.Time { return now }, refreshWindow(time.Hour))
			key := testKey(t)
			writeRecord(t, directory, key, cacheRecord{Version: cacheVersion, Credentials: *test.cached})
			fresh := testResult(now.Add(time.Hour))

			result, hit, err := store.GetOrRetrieve(key, func() (*config.AssumeRoleResult, error) { return fresh, nil })
			if err != nil {
				t.Fatalf("GetOrRetrieve() error = %v", err)
			}
			if hit || result != fresh {
				t.Errorf("GetOrRetrieve() = (%p, %v), want fresh result", result, hit)
			}
		})
	}
}

func TestStoreIgnoresMalformedAndUnknownCacheRecords(t *testing.T) {
	now := time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		content string
	}{
		{name: "malformed", content: "not JSON"},
		{name: "unknown version", content: `{"version":999}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			store := newStore(directory, func() time.Time { return now }, refreshWindow(time.Hour))
			key := testKey(t)
			if err := os.WriteFile(filepath.Join(directory, key+".json"), []byte(test.content), 0o600); err != nil {
				t.Fatalf("write cache: %v", err)
			}
			fresh := testResult(now.Add(time.Hour))
			result, hit, err := store.GetOrRetrieve(key, func() (*config.AssumeRoleResult, error) { return fresh, nil })
			if err != nil {
				t.Fatalf("GetOrRetrieve() error = %v", err)
			}
			if hit || result != fresh {
				t.Errorf("GetOrRetrieve() = (%p, %v), want fresh result", result, hit)
			}
		})
	}
}

func TestStoreDoesNotCacheShortLivedResult(t *testing.T) {
	now := time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)
	directory := t.TempDir()
	store := newStore(directory, func() time.Time { return now }, refreshWindow(15*time.Minute))
	key := testKey(t)
	shortLived := testResult(now.Add(refreshWindow(15 * time.Minute)))

	for range 2 {
		_, hit, err := store.GetOrRetrieve(key, func() (*config.AssumeRoleResult, error) { return shortLived, nil })
		if err != nil {
			t.Fatalf("GetOrRetrieve() error = %v", err)
		}
		if hit {
			t.Error("GetOrRetrieve() unexpectedly reused a short-lived result")
		}
	}
	if _, err := os.Stat(filepath.Join(directory, key+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("cache file error = %v, want not found", err)
	}
}
