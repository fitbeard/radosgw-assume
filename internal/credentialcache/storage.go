package credentialcache

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fitbeard/radosgw-assume/internal/config"
)

const cacheVersion = 1

type cacheRecord struct {
	Version     int                     `json:"version"`
	Credentials config.AssumeRoleResult `json:"credentials"`
}

func (store *Store) ensureDirectory() error {
	if err := os.MkdirAll(store.directory, 0o700); err != nil {
		return fmt.Errorf("create credential cache directory: %w", err)
	}
	directoryInfo, err := os.Lstat(store.directory)
	if err != nil {
		return fmt.Errorf("inspect credential cache directory: %w", err)
	}
	if !directoryInfo.IsDir() {
		return fmt.Errorf("credential cache path is not a directory")
	}
	if err := os.Chmod(store.directory, 0o700); err != nil {
		return fmt.Errorf("secure credential cache directory: %w", err)
	}
	return nil
}

func (store *Store) load(key string) (*config.AssumeRoleResult, bool, error) {
	cachePath := filepath.Join(store.directory, key+".json")
	encoded, err := os.ReadFile(cachePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read credential cache: %w", err)
	}

	var record cacheRecord
	if err := json.Unmarshal(encoded, &record); err != nil || record.Version != cacheVersion {
		if removeErr := os.Remove(cachePath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return nil, false, fmt.Errorf("remove invalid credential cache entry: %w", removeErr)
		}
		return nil, false, nil
	}
	if !store.isReusable(&record.Credentials) {
		if removeErr := os.Remove(cachePath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return nil, false, fmt.Errorf("remove stale credential cache entry: %w", removeErr)
		}
		return nil, false, nil
	}

	return &record.Credentials, true, nil
}

func (store *Store) write(key string, result *config.AssumeRoleResult) error {
	temporaryFile, err := os.CreateTemp(store.directory, ".credentials-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary credential cache: %w", err)
	}
	temporaryPath := temporaryFile.Name()
	defer func() { _ = os.Remove(temporaryPath) }()

	if err := temporaryFile.Chmod(0o600); err != nil {
		_ = temporaryFile.Close()
		return fmt.Errorf("secure temporary credential cache: %w", err)
	}
	record := cacheRecord{Version: cacheVersion, Credentials: *result}
	if err := json.NewEncoder(temporaryFile).Encode(record); err != nil {
		_ = temporaryFile.Close()
		return fmt.Errorf("write temporary credential cache: %w", err)
	}
	if err := temporaryFile.Sync(); err != nil {
		_ = temporaryFile.Close()
		return fmt.Errorf("sync temporary credential cache: %w", err)
	}
	if err := temporaryFile.Close(); err != nil {
		return fmt.Errorf("close temporary credential cache: %w", err)
	}

	cachePath := filepath.Join(store.directory, key+".json")
	if err := os.Rename(temporaryPath, cachePath); err != nil {
		return fmt.Errorf("replace credential cache: %w", err)
	}
	return nil
}
