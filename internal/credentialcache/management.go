package credentialcache

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Summary describes credential cache contents without exposing credentials or
// configuration-derived cache keys.
type Summary struct {
	Directory string
	Valid     int
	Expired   int
	Invalid   int
}

// Total returns the number of credential data entries in the cache.
func (summary Summary) Total() int {
	return summary.Valid + summary.Expired + summary.Invalid
}

// ClearResult describes a completed credential cache cleanup.
type ClearResult struct {
	Directory string
	Removed   int
}

// Inspect returns a non-secret summary of the default credential cache.
func Inspect() (Summary, error) {
	directory, err := defaultDirectory()
	if err != nil {
		return Summary{}, err
	}
	return newStore(directory, time.Now, 0).inspect()
}

// Clear removes all cached temporary credentials and orphaned temporary files.
func Clear() (ClearResult, error) {
	directory, err := defaultDirectory()
	if err != nil {
		return ClearResult{}, err
	}
	return newStore(directory, time.Now, 0).clear()
}

func (store *Store) inspect() (Summary, error) {
	summary := Summary{Directory: store.directory}
	exists, err := store.directoryExists()
	if err != nil || !exists {
		return summary, err
	}

	cacheLock, err := store.lockCache(unix.LOCK_SH)
	if err != nil {
		return Summary{}, err
	}
	defer unlockFile(cacheLock)

	entries, err := os.ReadDir(store.directory)
	if err != nil {
		return Summary{}, fmt.Errorf("read credential cache directory: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !isCredentialDataFile(entry.Name()) {
			continue
		}
		switch store.entryState(entry) {
		case entryValid:
			summary.Valid++
		case entryExpired:
			summary.Expired++
		case entryInvalid:
			summary.Invalid++
		}
	}
	return summary, nil
}

func (store *Store) clear() (ClearResult, error) {
	result := ClearResult{Directory: store.directory}
	exists, err := store.directoryExists()
	if err != nil || !exists {
		return result, err
	}

	cacheLock, err := store.lockCache(unix.LOCK_EX)
	if err != nil {
		return ClearResult{}, err
	}
	defer unlockFile(cacheLock)

	entries, err := os.ReadDir(store.directory)
	if err != nil {
		return ClearResult{}, fmt.Errorf("read credential cache directory: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !isCredentialDataFile(entry.Name()) {
			continue
		}
		if err := os.Remove(filepath.Join(store.directory, entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			return ClearResult{}, fmt.Errorf("remove credential cache entry: %w", err)
		}
		result.Removed++
	}
	return result, nil
}

func (store *Store) prune() error {
	cacheLock, err := store.lockCache(unix.LOCK_EX | unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		// Another cache operation is active. Cleanup is opportunistic and the
		// accessed key is still validated under its own lock below.
		return nil
	}
	if err != nil {
		return err
	}
	defer unlockFile(cacheLock)

	entries, err := os.ReadDir(store.directory)
	if err != nil {
		return fmt.Errorf("read credential cache directory: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !isCredentialDataFile(entry.Name()) {
			continue
		}
		state := store.entryState(entry)
		if state == entryValid {
			continue
		}
		if err := os.Remove(filepath.Join(store.directory, entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove stale credential cache entry: %w", err)
		}
	}
	return nil
}

func (store *Store) directoryExists() (bool, error) {
	info, err := os.Lstat(store.directory)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect credential cache directory: %w", err)
	}
	if !info.IsDir() {
		return false, fmt.Errorf("credential cache path is not a directory")
	}
	return true, nil
}

type cacheEntryState int

const (
	entryInvalid cacheEntryState = iota
	entryExpired
	entryValid
)

func (store *Store) entryState(entry os.DirEntry) cacheEntryState {
	if entry.Type()&os.ModeSymlink != 0 || isTemporaryCacheFile(entry.Name()) {
		return entryInvalid
	}
	key, found := strings.CutSuffix(entry.Name(), ".json")
	if !found || validateKey(key) != nil {
		return entryInvalid
	}
	info, err := entry.Info()
	if err != nil || !info.Mode().IsRegular() {
		return entryInvalid
	}

	encoded, err := os.ReadFile(filepath.Join(store.directory, entry.Name()))
	if err != nil {
		return entryInvalid
	}
	var record cacheRecord
	if err := json.Unmarshal(encoded, &record); err != nil || record.Version != cacheVersion {
		return entryInvalid
	}
	expiration, valid := credentialExpiration(&record.Credentials)
	if !valid {
		return entryInvalid
	}
	if !expiration.After(store.now()) {
		return entryExpired
	}
	return entryValid
}

func isCredentialDataFile(name string) bool {
	if isTemporaryCacheFile(name) {
		return true
	}
	return strings.HasSuffix(name, ".json")
}

func isTemporaryCacheFile(name string) bool {
	return strings.HasPrefix(name, ".credentials-") && strings.HasSuffix(name, ".tmp")
}
