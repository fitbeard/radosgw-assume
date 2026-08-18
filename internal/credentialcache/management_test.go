package credentialcache

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fitbeard/radosgw-assume/internal/config"

	"golang.org/x/sys/unix"
)

func TestStoreInspectAndClear(t *testing.T) {
	now := time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)
	directory := filepath.Join(t.TempDir(), "credentials-v1")
	store := newStore(directory, func() time.Time { return now }, 0)

	summary, err := store.inspect()
	if err != nil {
		t.Fatalf("inspect missing cache: %v", err)
	}
	if summary.Directory != directory || summary.Total() != 0 {
		t.Errorf("inspect missing cache = %+v, want empty summary for %s", summary, directory)
	}
	cleared, err := store.clear()
	if err != nil {
		t.Fatalf("clear missing cache: %v", err)
	}
	if cleared.Directory != directory || cleared.Removed != 0 {
		t.Errorf("clear missing cache = %+v, want zero removals from %s", cleared, directory)
	}

	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatalf("create cache directory: %v", err)
	}
	validKey := numberedKey(1)
	expiredKey := numberedKey(2)
	invalidKey := numberedKey(3)
	writeRecord(t, directory, validKey, cacheRecord{Version: cacheVersion, Credentials: *testResult(now.Add(time.Hour))})
	writeRecord(t, directory, expiredKey, cacheRecord{Version: cacheVersion, Credentials: *testResult(now.Add(-time.Second))})
	if err := os.WriteFile(filepath.Join(directory, invalidKey+".json"), []byte("not JSON"), 0o600); err != nil {
		t.Fatalf("write invalid cache record: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, ".credentials-orphan.tmp"), []byte("temporary credentials"), 0o600); err != nil {
		t.Fatalf("write orphaned temporary file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "keep.txt"), []byte("unrelated"), 0o600); err != nil {
		t.Fatalf("write unrelated file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, validKey+".lock"), nil, 0o600); err != nil {
		t.Fatalf("write per-key lock: %v", err)
	}

	summary, err = store.inspect()
	if err != nil {
		t.Fatalf("inspect populated cache: %v", err)
	}
	if summary.Valid != 1 || summary.Expired != 1 || summary.Invalid != 2 || summary.Total() != 4 {
		t.Errorf("inspect populated cache = %+v, want 1 valid, 1 expired, 2 invalid", summary)
	}

	cleared, err = store.clear()
	if err != nil {
		t.Fatalf("clear populated cache: %v", err)
	}
	if cleared.Removed != 4 {
		t.Errorf("clear removed = %d, want 4", cleared.Removed)
	}
	for _, name := range []string{"keep.txt", validKey + ".lock", cacheLockName} {
		if _, err := os.Stat(filepath.Join(directory, name)); err != nil {
			t.Errorf("preserved file %s: %v", name, err)
		}
	}
	summary, err = store.inspect()
	if err != nil {
		t.Fatalf("inspect cleared cache: %v", err)
	}
	if summary.Total() != 0 {
		t.Errorf("inspect cleared cache = %+v, want no entries", summary)
	}
}

func TestStoreAutomaticallyPrunesStaleEntries(t *testing.T) {
	now := time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)
	directory := t.TempDir()
	store := newStore(directory, func() time.Time { return now }, refreshWindow(time.Hour))
	activeKey := numberedKey(1)
	expiredKey := numberedKey(2)
	invalidKey := numberedKey(3)
	writeRecord(t, directory, activeKey, cacheRecord{Version: cacheVersion, Credentials: *testResult(now.Add(time.Hour))})
	writeRecord(t, directory, expiredKey, cacheRecord{Version: cacheVersion, Credentials: *testResult(now.Add(-time.Second))})
	if err := os.WriteFile(filepath.Join(directory, invalidKey+".json"), []byte("{"), 0o600); err != nil {
		t.Fatalf("write invalid cache record: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, ".credentials-orphan.tmp"), []byte("partial"), 0o600); err != nil {
		t.Fatalf("write orphaned temporary file: %v", err)
	}

	result, hit, err := store.GetOrRetrieve(activeKey, func() (*config.AssumeRoleResult, error) {
		t.Fatal("active cache entry unexpectedly triggered retrieval")
		return nil, nil
	})
	if err != nil {
		t.Fatalf("GetOrRetrieve() error = %v", err)
	}
	if !hit || result.AccessKeyID == "" {
		t.Errorf("GetOrRetrieve() = (%+v, %v), want active cache hit", result, hit)
	}
	for _, name := range []string{expiredKey + ".json", invalidKey + ".json", ".credentials-orphan.tmp"} {
		if _, err := os.Stat(filepath.Join(directory, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("stale cache file %s error = %v, want not found", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(directory, activeKey+".json")); err != nil {
		t.Errorf("active cache entry was removed: %v", err)
	}
}

func TestStorePruneDoesNotWaitForActiveCacheOperation(t *testing.T) {
	directory := t.TempDir()
	store := newStore(directory, time.Now, 0)
	cacheLock, err := store.lockCache(unix.LOCK_SH)
	if err != nil {
		t.Fatalf("acquire shared cache lock: %v", err)
	}
	defer unlockFile(cacheLock)

	done := make(chan error, 1)
	go func() { done <- store.prune() }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("prune() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("prune() blocked behind an active cache operation")
	}
}

func TestDefaultInspectAndClear(t *testing.T) {
	cacheRoot := t.TempDir()
	t.Setenv("HOME", cacheRoot)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(cacheRoot, "cache"))
	store, err := New(time.Hour)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	now := time.Now()
	key := numberedKey(1)
	if _, _, err := store.GetOrRetrieve(key, func() (*config.AssumeRoleResult, error) {
		return testResult(now.Add(time.Hour)), nil
	}); err != nil {
		t.Fatalf("populate default cache: %v", err)
	}

	summary, err := Inspect()
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if summary.Directory != store.directory || summary.Valid != 1 || summary.Total() != 1 {
		t.Errorf("Inspect() = %+v, want one valid entry in %s", summary, store.directory)
	}
	result, err := Clear()
	if err != nil {
		t.Fatalf("Clear() error = %v", err)
	}
	if result.Directory != store.directory || result.Removed != 1 {
		t.Errorf("Clear() = %+v, want one removal from %s", result, store.directory)
	}
}

func TestStoreRemovesUnusableEntryWhenRetrievalFails(t *testing.T) {
	now := time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)
	directory := t.TempDir()
	store := newStore(directory, func() time.Time { return now }, refreshWindow(time.Hour))
	key := numberedKey(1)
	writeRecord(t, directory, key, cacheRecord{Version: cacheVersion, Credentials: *testResult(now.Add(time.Minute))})
	wantErr := errors.New("authentication failed")

	if _, _, err := store.GetOrRetrieve(key, func() (*config.AssumeRoleResult, error) { return nil, wantErr }); !errors.Is(err, wantErr) {
		t.Errorf("GetOrRetrieve() error = %v, want %v", err, wantErr)
	}
	if _, err := os.Stat(filepath.Join(directory, key+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("unusable cache file error = %v, want not found", err)
	}
}

func TestStoreManagementRejectsNonDirectoryPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache-file")
	if err := os.WriteFile(path, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write cache path: %v", err)
	}
	store := newStore(path, time.Now, 0)
	if _, err := store.inspect(); err == nil {
		t.Error("inspect() expected a non-directory error")
	}
	if _, err := store.clear(); err == nil {
		t.Error("clear() expected a non-directory error")
	}
}
