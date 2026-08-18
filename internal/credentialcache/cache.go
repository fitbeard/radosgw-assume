package credentialcache

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fitbeard/radosgw-assume/internal/config"

	"golang.org/x/sys/unix"
)

const (
	minimumValidity = time.Minute
	maximumValidity = 15 * time.Minute
)

// Store persists temporary STS credentials in a user-private cache.
type Store struct {
	directory       string
	now             func() time.Time
	minimumValidity time.Duration
}

// New returns a credential store under the operating system's user cache
// directory.
func New(sessionDuration time.Duration) (*Store, error) {
	directory, err := defaultDirectory()
	if err != nil {
		return nil, err
	}

	return newStore(
		directory,
		time.Now,
		refreshWindow(sessionDuration),
	), nil
}

func defaultDirectory() (string, error) {
	userCacheDirectory, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("find user cache directory: %w", err)
	}
	return filepath.Join(userCacheDirectory, "radosgw-assume", "credentials-v1"), nil
}

func newStore(directory string, now func() time.Time, validityWindow time.Duration) *Store {
	return &Store{directory: directory, now: now, minimumValidity: validityWindow}
}

func refreshWindow(sessionDuration time.Duration) time.Duration {
	window := sessionDuration / 10
	if window < minimumValidity {
		return minimumValidity
	}
	if window > maximumValidity {
		return maximumValidity
	}
	return window
}

// GetOrRetrieve returns a reusable cached result or obtains and atomically
// stores a fresh one while holding a per-key process lock.
func (store *Store) GetOrRetrieve(key string, retrieve func() (*config.AssumeRoleResult, error)) (*config.AssumeRoleResult, bool, error) {
	if err := validateKey(key); err != nil {
		return nil, false, err
	}
	if retrieve == nil {
		return nil, false, fmt.Errorf("retrieve credentials callback is missing")
	}
	if err := store.ensureDirectory(); err != nil {
		return nil, false, err
	}
	if err := store.prune(); err != nil {
		return nil, false, err
	}

	cacheLock, err := store.lockCache(unix.LOCK_SH)
	if err != nil {
		return nil, false, err
	}
	defer unlockFile(cacheLock)

	lockFile, err := store.lock(key)
	if err != nil {
		return nil, false, err
	}
	defer func() {
		unlockFile(lockFile)
	}()

	result, found, err := store.load(key)
	if err != nil {
		return nil, false, err
	}
	if found {
		return result, true, nil
	}

	result, err = retrieve()
	if err != nil {
		return nil, false, err
	}
	if result == nil {
		return nil, false, fmt.Errorf("credential retrieval returned no result")
	}
	if store.isReusable(result) {
		if err := store.write(key, result); err != nil {
			return nil, false, err
		}
	}

	return result, false, nil
}
