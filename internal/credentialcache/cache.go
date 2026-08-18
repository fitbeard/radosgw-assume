package credentialcache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fitbeard/radosgw-assume/internal/config"

	"golang.org/x/sys/unix"
)

const (
	cacheVersion    = 1
	cacheKeyVersion = 1
	minimumValidity = time.Minute
	maximumValidity = 15 * time.Minute
	cacheLockName   = ".cache.lock"
)

// Store persists temporary STS credentials in a user-private cache.
type Store struct {
	directory       string
	now             func() time.Time
	minimumValidity time.Duration
}

type cacheRecord struct {
	Version     int                     `json:"version"`
	Credentials config.AssumeRoleResult `json:"credentials"`
}

type cacheKeyInput struct {
	Version           int    `json:"version"`
	ProfileName       string `json:"profile_name"`
	EndpointURL       string `json:"endpoint_url"`
	OIDCProvider      string `json:"oidc_provider"`
	OIDCClientID      string `json:"oidc_client_id"`
	OIDCAuthType      string `json:"oidc_auth_type"`
	OIDCScope         string `json:"oidc_scope"`
	OIDCPKCEMethod    string `json:"oidc_pkce_method"`
	SSLVerify         string `json:"ssl_verify"`
	RoleARN           string `json:"role_arn"`
	RoleSessionName   string `json:"role_session_name"`
	SessionDuration   int64  `json:"session_duration_nanoseconds"`
	OIDCTokenIdentity string `json:"oidc_token_identity,omitempty"`
}

// Key returns a stable, non-secret cache key for an effective profile.
func Key(profileName string, profileConfig *config.ProfileConfig, sessionDuration time.Duration, oidcToken string) (string, error) {
	if profileConfig == nil {
		return "", fmt.Errorf("create credential cache key: profile configuration is missing")
	}

	tokenIdentity := ""
	if profileConfig.RadosGWOIDCAuthType == "token" {
		tokenHash := sha256.Sum256([]byte(oidcToken))
		tokenIdentity = hex.EncodeToString(tokenHash[:])
	}

	input := cacheKeyInput{
		Version:           cacheKeyVersion,
		ProfileName:       profileName,
		EndpointURL:       profileConfig.EndpointURL,
		OIDCProvider:      profileConfig.RadosGWOIDCProvider,
		OIDCClientID:      profileConfig.RadosGWOIDCClientID,
		OIDCAuthType:      profileConfig.RadosGWOIDCAuthType,
		OIDCScope:         profileConfig.RadosGWOIDCScope,
		OIDCPKCEMethod:    profileConfig.RadosGWOIDCPKCEMethod,
		SSLVerify:         profileConfig.RadosGWSSLVerify,
		RoleARN:           profileConfig.RoleArn,
		RoleSessionName:   profileConfig.RoleSessionName,
		SessionDuration:   int64(sessionDuration),
		OIDCTokenIdentity: tokenIdentity,
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		return "", fmt.Errorf("create credential cache key: %w", err)
	}

	keyHash := sha256.Sum256(encoded)
	return hex.EncodeToString(keyHash[:]), nil
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

func (store *Store) lockCache(mode int) (*os.File, error) {
	lockPath := filepath.Join(store.directory, cacheLockName)
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open credential cache management lock: %w", err)
	}
	if err := os.Chmod(lockPath, 0o600); err != nil {
		_ = lockFile.Close()
		return nil, fmt.Errorf("secure credential cache management lock: %w", err)
	}
	if err := unix.Flock(int(lockFile.Fd()), mode); err != nil {
		_ = lockFile.Close()
		return nil, fmt.Errorf("lock credential cache: %w", err)
	}
	return lockFile, nil
}

func unlockFile(file *os.File) {
	_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
	_ = file.Close()
}

func validateKey(key string) error {
	if len(key) != sha256.Size*2 {
		return fmt.Errorf("invalid credential cache key")
	}
	if _, err := hex.DecodeString(key); err != nil {
		return fmt.Errorf("invalid credential cache key: %w", err)
	}
	return nil
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

func (store *Store) lock(key string) (*os.File, error) {
	lockPath := filepath.Join(store.directory, key+".lock")
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open credential cache lock: %w", err)
	}
	if err := os.Chmod(lockPath, 0o600); err != nil {
		_ = lockFile.Close()
		return nil, fmt.Errorf("secure credential cache lock: %w", err)
	}
	if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX); err != nil {
		_ = lockFile.Close()
		return nil, fmt.Errorf("lock credential cache: %w", err)
	}
	return lockFile, nil
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

func (store *Store) isReusable(result *config.AssumeRoleResult) bool {
	expiration, valid := credentialExpiration(result)
	if !valid {
		return false
	}
	return expiration.After(store.now().Add(store.minimumValidity))
}

func credentialExpiration(result *config.AssumeRoleResult) (time.Time, bool) {
	if result == nil || result.AccessKeyID == "" || result.SecretAccessKey == "" || result.SessionToken == "" {
		return time.Time{}, false
	}
	expiration, err := time.Parse(time.RFC3339, result.Expiration)
	return expiration, err == nil
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
