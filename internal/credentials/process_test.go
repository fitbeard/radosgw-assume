package credentials

import (
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fitbeard/radosgw-assume/internal/config"
	"github.com/fitbeard/radosgw-assume/internal/credentialcache"

	"gopkg.in/ini.v1"
)

type testProcessCredentialCache struct {
	key      string
	result   *config.AssumeRoleResult
	hit      bool
	err      error
	retrieve bool
}

func (cache *testProcessCredentialCache) GetOrRetrieve(key string, retrieve func() (*config.AssumeRoleResult, error)) (*config.AssumeRoleResult, bool, error) {
	cache.key = key
	if cache.err != nil {
		return nil, false, cache.err
	}
	if cache.retrieve {
		result, err := retrieve()
		return result, false, err
	}
	return cache.result, cache.hit, nil
}

func TestGetProcessCredentialsBypassesCache(t *testing.T) {
	profileConfig := processTestProfile()
	want := processTestResult()
	dependencies := processTestDependencies(t)
	dependencies.getCredentials = func(profileName string, gotProfile *config.ProfileConfig, awsConfig *ini.File, verbose bool, duration time.Duration, output io.Writer) (*config.AssumeRoleResult, error) {
		if profileName != "profile" || gotProfile != profileConfig || awsConfig != nil || !verbose || duration != 12*time.Hour || output == nil {
			t.Error("getCredentials() received unexpected arguments")
		}
		return want, nil
	}

	var output bytes.Buffer
	result, err := getProcessCredentials("profile", profileConfig, nil, true, 12*time.Hour, &output, true, dependencies)
	if err != nil {
		t.Fatalf("getProcessCredentials() error = %v", err)
	}
	if result != want {
		t.Errorf("getProcessCredentials() result = %p, want %p", result, want)
	}
	if !strings.Contains(output.String(), "Configure the AWS consumer endpoint separately: https://storage.example.com") {
		t.Errorf("output = %q, want endpoint configuration reminder", output.String())
	}
}

func TestGetProcessCredentialsCachesResolvedProfile(t *testing.T) {
	profileConfig := &config.ProfileConfig{SourceProfile: "base", RoleArn: "arn:derived"}
	effectiveConfig := processTestProfile()
	want := processTestResult()
	cache := &testProcessCredentialCache{retrieve: true}
	dependencies := processTestDependencies(t)
	dependencies.resolveSourceProfile = func(gotProfile *config.ProfileConfig, gotConfig *ini.File, verbose bool) (*config.ProfileConfig, error) {
		if gotProfile != profileConfig || gotConfig != nil || verbose {
			t.Error("resolveSourceProfile() received unexpected arguments")
		}
		return effectiveConfig, nil
	}
	dependencies.getenv = func(name string) string {
		if name != "RADOSGW_OIDC_TOKEN" {
			t.Errorf("getenv() name = %q", name)
		}
		return "ignored-device-token"
	}
	dependencies.newCache = func(duration time.Duration) (processCredentialCache, error) {
		if duration != time.Hour {
			t.Errorf("newCache() duration = %v, want 1h", duration)
		}
		return cache, nil
	}
	dependencies.getCredentials = func(string, *config.ProfileConfig, *ini.File, bool, time.Duration, io.Writer) (*config.AssumeRoleResult, error) {
		return want, nil
	}

	result, err := getProcessCredentials("profile", profileConfig, nil, false, time.Hour, &bytes.Buffer{}, false, dependencies)
	if err != nil {
		t.Fatalf("getProcessCredentials() error = %v", err)
	}
	if result != want || cache.key == "" {
		t.Errorf("getProcessCredentials() = (%p, key %q), want fresh cached result", result, cache.key)
	}
}

func TestGetProcessCredentialsReportsCacheHit(t *testing.T) {
	want := processTestResult()
	cache := &testProcessCredentialCache{result: want, hit: true}
	dependencies := processTestDependencies(t)
	dependencies.resolveSourceProfile = func(profile *config.ProfileConfig, _ *ini.File, _ bool) (*config.ProfileConfig, error) {
		return profile, nil
	}
	dependencies.getenv = func(string) string { return "" }
	dependencies.newCache = func(time.Duration) (processCredentialCache, error) { return cache, nil }
	var output bytes.Buffer

	result, err := getProcessCredentials("profile", processTestProfile(), nil, true, time.Hour, &output, false, dependencies)
	if err != nil {
		t.Fatalf("getProcessCredentials() error = %v", err)
	}
	if result != want {
		t.Errorf("getProcessCredentials() result = %p, want %p", result, want)
	}
	if !strings.Contains(output.String(), "# Using cached credentials for profile: profile") {
		t.Errorf("output = %q, want cache hit message", output.String())
	}
	if strings.Contains(output.String(), "consumer endpoint") {
		t.Errorf("output = %q, must not repeat endpoint configuration reminder on a cache hit", output.String())
	}
}

func TestGetProcessCredentialsHidesEndpointReminderWithoutVerbose(t *testing.T) {
	want := processTestResult()
	cache := &testProcessCredentialCache{result: want, hit: true}
	dependencies := processTestDependencies(t)
	dependencies.resolveSourceProfile = func(profile *config.ProfileConfig, _ *ini.File, _ bool) (*config.ProfileConfig, error) {
		return profile, nil
	}
	dependencies.getenv = func(string) string { return "" }
	dependencies.newCache = func(time.Duration) (processCredentialCache, error) { return cache, nil }
	var output bytes.Buffer

	if _, err := getProcessCredentials("profile", processTestProfile(), nil, false, time.Hour, &output, false, dependencies); err != nil {
		t.Fatalf("getProcessCredentials() error = %v", err)
	}
	if output.Len() != 0 {
		t.Errorf("output = %q, want no non-verbose output", output.String())
	}
}

func TestGetProcessCredentialsUsesDefaultCache(t *testing.T) {
	cacheRoot := t.TempDir()
	t.Setenv("HOME", cacheRoot)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(cacheRoot, "cache"))
	profile := processTestProfile()
	want := processTestResult()
	want.Expiration = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	key, err := credentialcache.Key("profile", profile, time.Hour, "")
	if err != nil {
		t.Fatalf("credentialcache.Key() error = %v", err)
	}
	cache, err := credentialcache.New(time.Hour)
	if err != nil {
		t.Fatalf("credentialcache.New() error = %v", err)
	}
	if _, _, err := cache.GetOrRetrieve(key, func() (*config.AssumeRoleResult, error) { return want, nil }); err != nil {
		t.Fatalf("populate cache: %v", err)
	}

	var output bytes.Buffer
	result, err := GetProcessCredentials("profile", profile, nil, true, time.Hour, &output, false)
	if err != nil {
		t.Fatalf("GetProcessCredentials() error = %v", err)
	}
	if result.AccessKeyID != want.AccessKeyID {
		t.Errorf("GetProcessCredentials() access key = %q, want cached value", result.AccessKeyID)
	}
	if !strings.Contains(output.String(), "# Using cached credentials for profile: profile") {
		t.Errorf("output = %q, want cache hit message", output.String())
	}
}

func TestGetProcessCredentialsErrors(t *testing.T) {
	tests := []struct {
		name        string
		configure   func(*processCredentialDependencies)
		wantMessage string
	}{
		{
			name: "source profile",
			configure: func(dependencies *processCredentialDependencies) {
				dependencies.resolveSourceProfile = func(*config.ProfileConfig, *ini.File, bool) (*config.ProfileConfig, error) {
					return nil, errors.New("source failure")
				}
			},
			wantMessage: "source failure",
		},
		{
			name: "cache initialization",
			configure: func(dependencies *processCredentialDependencies) {
				dependencies.resolveSourceProfile = func(profile *config.ProfileConfig, _ *ini.File, _ bool) (*config.ProfileConfig, error) {
					return profile, nil
				}
				dependencies.getenv = func(string) string { return "" }
				dependencies.newCache = func(time.Duration) (processCredentialCache, error) { return nil, errors.New("cache failure") }
			},
			wantMessage: "initialize credential cache: cache failure",
		},
		{
			name: "cache operation",
			configure: func(dependencies *processCredentialDependencies) {
				dependencies.resolveSourceProfile = func(profile *config.ProfileConfig, _ *ini.File, _ bool) (*config.ProfileConfig, error) {
					return profile, nil
				}
				dependencies.getenv = func(string) string { return "" }
				dependencies.newCache = func(time.Duration) (processCredentialCache, error) {
					return &testProcessCredentialCache{err: errors.New("operation failure")}, nil
				}
			},
			wantMessage: "operation failure",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dependencies := processTestDependencies(t)
			test.configure(&dependencies)
			_, err := getProcessCredentials("profile", processTestProfile(), nil, false, time.Hour, &bytes.Buffer{}, false, dependencies)
			if err == nil || !strings.Contains(err.Error(), test.wantMessage) {
				t.Errorf("getProcessCredentials() error = %v, want %q", err, test.wantMessage)
			}
		})
	}
}

func processTestDependencies(t *testing.T) processCredentialDependencies {
	t.Helper()
	return processCredentialDependencies{
		resolveSourceProfile: func(*config.ProfileConfig, *ini.File, bool) (*config.ProfileConfig, error) {
			t.Fatal("unexpected resolveSourceProfile() call")
			return nil, nil
		},
		getenv: func(string) string {
			t.Fatal("unexpected getenv() call")
			return ""
		},
		newCache: func(time.Duration) (processCredentialCache, error) {
			t.Fatal("unexpected newCache() call")
			return nil, nil
		},
		getCredentials: func(string, *config.ProfileConfig, *ini.File, bool, time.Duration, io.Writer) (*config.AssumeRoleResult, error) {
			t.Fatal("unexpected getCredentials() call")
			return nil, nil
		},
	}
}

func processTestProfile() *config.ProfileConfig {
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

func processTestResult() *config.AssumeRoleResult {
	return &config.AssumeRoleResult{
		AccessKeyID:     "access-key",
		SecretAccessKey: "secret-key",
		SessionToken:    "session-token",
		Expiration:      "2030-01-01T01:00:00Z",
		ProfileName:     "profile",
		EndpointURL:     "https://storage.example.com",
	}
}
