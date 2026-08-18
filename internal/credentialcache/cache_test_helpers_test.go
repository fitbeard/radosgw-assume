package credentialcache

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fitbeard/radosgw-assume/internal/config"
)

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

func numberedKey(number int) string {
	return fmt.Sprintf("%064x", number)
}
