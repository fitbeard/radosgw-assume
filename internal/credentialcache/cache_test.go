package credentialcache

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fitbeard/radosgw-assume/internal/config"
)

func TestKey(t *testing.T) {
	profileConfig := testProfileConfig()
	baseKey, err := Key("profile", profileConfig, time.Hour, "")
	if err != nil {
		t.Fatalf("Key() error = %v", err)
	}
	if len(baseKey) != 64 {
		t.Fatalf("Key() length = %d, want 64", len(baseKey))
	}

	tests := []struct {
		name      string
		profile   string
		configure func(*config.ProfileConfig)
		duration  time.Duration
		oidcToken string
	}{
		{name: "profile name", profile: "other", duration: time.Hour},
		{name: "endpoint", profile: "profile", configure: func(profile *config.ProfileConfig) { profile.EndpointURL = "https://other.example.com" }, duration: time.Hour},
		{name: "provider", profile: "profile", configure: func(profile *config.ProfileConfig) { profile.RadosGWOIDCProvider = "https://other-idp.example.com" }, duration: time.Hour},
		{name: "client ID", profile: "profile", configure: func(profile *config.ProfileConfig) { profile.RadosGWOIDCClientID = "other-client" }, duration: time.Hour},
		{name: "auth type", profile: "profile", configure: func(profile *config.ProfileConfig) { profile.RadosGWOIDCAuthType = "browser" }, duration: time.Hour},
		{name: "scope", profile: "profile", configure: func(profile *config.ProfileConfig) { profile.RadosGWOIDCScope = "openid email" }, duration: time.Hour},
		{name: "PKCE", profile: "profile", configure: func(profile *config.ProfileConfig) { profile.RadosGWOIDCPKCEMethod = "plain" }, duration: time.Hour},
		{name: "TLS", profile: "profile", configure: func(profile *config.ProfileConfig) { profile.RadosGWSSLVerify = "false" }, duration: time.Hour},
		{name: "role", profile: "profile", configure: func(profile *config.ProfileConfig) { profile.RoleArn = "arn:other" }, duration: time.Hour},
		{name: "session", profile: "profile", configure: func(profile *config.ProfileConfig) { profile.RoleSessionName = "other-session" }, duration: time.Hour},
		{name: "duration", profile: "profile", duration: 2 * time.Hour},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profile := testProfileConfig()
			if test.configure != nil {
				test.configure(profile)
			}
			key, err := Key(test.profile, profile, test.duration, test.oidcToken)
			if err != nil {
				t.Fatalf("Key() error = %v", err)
			}
			if key == baseKey {
				t.Errorf("Key() = %q, want configuration-specific key", key)
			}
		})
	}
}

func TestKeyUsesTokenIdentityOnlyForTokenAuthentication(t *testing.T) {
	profile := testProfileConfig()
	deviceKey, err := Key("profile", profile, time.Hour, "first-token")
	if err != nil {
		t.Fatalf("Key() error = %v", err)
	}
	otherDeviceKey, err := Key("profile", profile, time.Hour, "second-token")
	if err != nil {
		t.Fatalf("Key() error = %v", err)
	}
	if deviceKey != otherDeviceKey {
		t.Error("device cache key unexpectedly includes an environment token")
	}

	profile.RadosGWOIDCAuthType = "token"
	tokenKey, err := Key("profile", profile, time.Hour, "first-token")
	if err != nil {
		t.Fatalf("Key() error = %v", err)
	}
	otherTokenKey, err := Key("profile", profile, time.Hour, "second-token")
	if err != nil {
		t.Fatalf("Key() error = %v", err)
	}
	if tokenKey == otherTokenKey {
		t.Error("token cache key must distinguish source token identities")
	}
}

func TestKeyRejectsMissingConfiguration(t *testing.T) {
	if _, err := Key("profile", nil, time.Hour, ""); err == nil {
		t.Fatal("Key() expected an error")
	}
}

func TestRefreshWindow(t *testing.T) {
	tests := []struct {
		duration time.Duration
		want     time.Duration
	}{
		{duration: 5 * time.Minute, want: time.Minute},
		{duration: 15 * time.Minute, want: 90 * time.Second},
		{duration: time.Hour, want: 6 * time.Minute},
		{duration: 12 * time.Hour, want: 15 * time.Minute},
	}
	for _, test := range tests {
		if got := refreshWindow(test.duration); got != test.want {
			t.Errorf("refreshWindow(%v) = %v, want %v", test.duration, got, test.want)
		}
	}
}

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
	assertMode(t, filepath.Join(directory, key+".lock"), 0o600)
	assertMode(t, filepath.Join(directory, key+".json"), 0o600)
}

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

func TestStoreSerializesConcurrentRetrieval(t *testing.T) {
	now := time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)
	store := newStore(t.TempDir(), func() time.Time { return now }, refreshWindow(time.Hour))
	key := testKey(t)
	want := testResult(now.Add(time.Hour))
	started := make(chan struct{})
	release := make(chan struct{})
	var retrievals atomic.Int32
	retrieve := func() (*config.AssumeRoleResult, error) {
		if retrievals.Add(1) == 1 {
			close(started)
		}
		<-release
		return want, nil
	}

	const callers = 8
	var waitGroup sync.WaitGroup
	waitGroup.Add(callers)
	errorsChannel := make(chan error, callers)
	for range callers {
		go func() {
			defer waitGroup.Done()
			result, _, err := store.GetOrRetrieve(key, retrieve)
			if err == nil && result.AccessKeyID != want.AccessKeyID {
				err = errors.New("unexpected cached result")
			}
			errorsChannel <- err
		}()
	}
	<-started
	close(release)
	waitGroup.Wait()
	close(errorsChannel)

	for err := range errorsChannel {
		if err != nil {
			t.Errorf("GetOrRetrieve() error = %v", err)
		}
	}
	if retrievals.Load() != 1 {
		t.Errorf("retrievals = %d, want 1", retrievals.Load())
	}
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

func testProfileConfig() *config.ProfileConfig {
	return &config.ProfileConfig{
		EndpointURL:           "https://storage.example.com",
		RadosGWOIDCProvider:   "https://idp.example.com/realms/test",
		RadosGWOIDCClientID:   "client",
		RadosGWOIDCAuthType:   "device",
		RadosGWOIDCScope:      "openid",
		RadosGWOIDCPKCEMethod: "S256",
		RadosGWSSLVerify:      "true",
		RoleArn:               "arn:role",
		RoleSessionName:       "session",
	}
}

func testKey(t *testing.T) string {
	t.Helper()
	key, err := Key("profile", testProfileConfig(), time.Hour, "")
	if err != nil {
		t.Fatalf("Key() error = %v", err)
	}
	return key
}

func testResult(expiration time.Time) *config.AssumeRoleResult {
	return &config.AssumeRoleResult{
		AccessKeyID:     "access-key",
		SecretAccessKey: "secret-key",
		SessionToken:    "session-token",
		Expiration:      expiration.Format(time.RFC3339),
		ProfileName:     "profile",
		EndpointURL:     "https://storage.example.com",
		AssumedRoleArn:  "arn:assumed-role",
	}
}

func writeRecord(t *testing.T, directory, key string, record cacheRecord) {
	t.Helper()
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal cache record: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, key+".json"), encoded, 0o600); err != nil {
		t.Fatalf("write cache record: %v", err)
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("mode for %s = %o, want %o", path, got, want)
	}
}
