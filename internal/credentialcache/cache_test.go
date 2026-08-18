package credentialcache

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/fitbeard/radosgw-assume/internal/config"
)

func TestStoreGetOrRetrieve(t *testing.T) {
	now := time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)
	directory := filepath.Join(t.TempDir(), "cache")
	store := newStore(directory, func() time.Time { return now }, refreshWindow(time.Hour))
	key := testKey(t)
	want := testResult(now.Add(time.Hour))
	retrievals := 0
	retrieve := func() (*config.AssumeRoleResult, error) {
		retrievals++
		return want, nil
	}

	result, hit, err := store.GetOrRetrieve(key, retrieve)
	if err != nil {
		t.Fatalf("first GetOrRetrieve() error = %v", err)
	}
	if hit || result != want {
		t.Errorf("first GetOrRetrieve() = (%p, %v), want fresh result", result, hit)
	}

	result, hit, err = store.GetOrRetrieve(key, retrieve)
	if err != nil {
		t.Fatalf("second GetOrRetrieve() error = %v", err)
	}
	if !hit || result == want || result.AccessKeyID != want.AccessKeyID {
		t.Errorf("second GetOrRetrieve() = (%#v, %v), want decoded cache hit", result, hit)
	}
	if retrievals != 1 {
		t.Errorf("retrievals = %d, want 1", retrievals)
	}

	assertMode(t, directory, 0o700)
	assertMode(t, filepath.Join(directory, cacheLockName), 0o600)
	assertMode(t, filepath.Join(directory, key+".lock"), 0o600)
	assertMode(t, filepath.Join(directory, key+".json"), 0o600)
}

func TestStoreErrors(t *testing.T) {
	now := time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)
	store := newStore(t.TempDir(), func() time.Time { return now }, refreshWindow(time.Hour))
	if _, _, err := store.GetOrRetrieve("invalid", func() (*config.AssumeRoleResult, error) { return nil, nil }); err == nil {
		t.Error("invalid key expected an error")
	}
	if _, _, err := store.GetOrRetrieve(testKey(t), nil); err == nil {
		t.Error("nil callback expected an error")
	}
	wantErr := errors.New("authentication failed")
	if _, _, err := store.GetOrRetrieve(testKey(t), func() (*config.AssumeRoleResult, error) { return nil, wantErr }); !errors.Is(err, wantErr) {
		t.Errorf("retrieval error = %v, want %v", err, wantErr)
	}
}
