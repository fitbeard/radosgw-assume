package credentials

import (
	"bytes"
	"context"
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
	dependencies.getCredentials = func(_ context.Context, options RequestOptions) (*config.AssumeRoleResult, error) {
		if options.ProfileName != "profile" || options.ProfileConfig != profileConfig || options.AWSConfig != nil || !options.Verbose || options.SessionDuration != 12*time.Hour || options.Output == nil {
			t.Error("getCredentials() received unexpected arguments")
		}
		return want, nil
	}

	var output bytes.Buffer
	result, err := getProcessCredentials(t.Context(), ProcessRequestOptions{
		RequestOptions: RequestOptions{
			ProfileName:     "profile",
			ProfileConfig:   profileConfig,
			Verbose:         true,
			SessionDuration: 12 * time.Hour,
			Output:          &output,
		},
		NoCache: true,
	}, dependencies)
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

func TestGetProcessCredentialsHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := GetProcessCredentials(ctx, ProcessRequestOptions{RequestOptions: RequestOptions{
		ProfileName:     "profile",
		ProfileConfig:   processTestProfile(),
		SessionDuration: time.Hour,
		Output:          io.Discard,
	}})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("GetProcessCredentials() error = %v, want context cancellation", err)
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
	dependencies.getCredentials = func(context.Context, RequestOptions) (*config.AssumeRoleResult, error) {
		return want, nil
	}

	result, err := getProcessCredentials(t.Context(), ProcessRequestOptions{RequestOptions: RequestOptions{
		ProfileName:     "profile",
		ProfileConfig:   profileConfig,
		SessionDuration: time.Hour,
		Output:          &bytes.Buffer{},
	}}, dependencies)
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

	result, err := getProcessCredentials(t.Context(), ProcessRequestOptions{RequestOptions: RequestOptions{
		ProfileName:     "profile",
		ProfileConfig:   processTestProfile(),
		Verbose:         true,
		SessionDuration: time.Hour,
		Output:          &output,
	}}, dependencies)
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

	if _, err := getProcessCredentials(t.Context(), ProcessRequestOptions{RequestOptions: RequestOptions{
		ProfileName:     "profile",
		ProfileConfig:   processTestProfile(),
		SessionDuration: time.Hour,
		Output:          &output,
	}}, dependencies); err != nil {
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
	result, err := GetProcessCredentials(t.Context(), ProcessRequestOptions{RequestOptions: RequestOptions{
		ProfileName:     "profile",
		ProfileConfig:   profile,
		Verbose:         true,
		SessionDuration: time.Hour,
		Output:          &output,
	}})
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
			_, err := getProcessCredentials(t.Context(), ProcessRequestOptions{RequestOptions: RequestOptions{
				ProfileName:     "profile",
				ProfileConfig:   processTestProfile(),
				SessionDuration: time.Hour,
				Output:          &bytes.Buffer{},
			}}, dependencies)
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
		getCredentials: func(context.Context, RequestOptions) (*config.AssumeRoleResult, error) {
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
