package credentials

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fitbeard/radosgw-assume/internal/config"

	"gopkg.in/ini.v1"
)

func TestGetCredentials(t *testing.T) {
	// Test error cases for GetCredentials function

	// Create minimal config for testing
	awsConfig := ini.Empty()

	// Test with missing endpoint URL
	profileConfig := &config.ProfileConfig{
		RoleArn: "arn:aws:iam::123456789012:role/TestRole",
	}

	_, err := GetCredentials("test-profile", profileConfig, awsConfig, false, time.Hour)
	if err == nil {
		t.Error("GetCredentials() with missing endpoint URL should return error")
	}
	if !strings.Contains(err.Error(), "endpoint_url") {
		t.Errorf("GetCredentials() should mention missing endpoint_url, got: %v", err)
	}

	// Test with missing role ARN
	profileConfigNoRole := &config.ProfileConfig{
		EndpointURL: "https://test.example.com",
	}

	_, err = GetCredentials("test-profile", profileConfigNoRole, awsConfig, false, time.Hour)
	if err == nil {
		t.Error("GetCredentials() with missing role ARN should return error")
	}
	if !strings.Contains(err.Error(), "role_arn") {
		t.Errorf("GetCredentials() should mention missing role_arn, got: %v", err)
	}

	// Test with missing OIDC provider (non-token auth)
	profileConfigNoOIDC := &config.ProfileConfig{
		EndpointURL: "https://test.example.com",
		RoleArn:     "arn:aws:iam::123456789012:role/TestRole",
		// Missing RadosGWOIDCProvider and RadosGWOIDCClientID
	}

	_, err = GetCredentials("test-profile", profileConfigNoOIDC, awsConfig, false, time.Hour)
	if err == nil {
		t.Error("GetCredentials() with missing OIDC provider should return error")
	}
	if !strings.Contains(err.Error(), "radosgw_oidc_provider") {
		t.Errorf("GetCredentials() should mention missing radosgw_oidc_provider, got: %v", err)
	}
}

func TestGetCredentials_TokenAuth(t *testing.T) {
	// Test token authentication type

	// Save original env
	originalToken := os.Getenv("RADOSGW_OIDC_TOKEN")
	defer func() { _ = os.Setenv("RADOSGW_OIDC_TOKEN", originalToken) }()

	awsConfig := ini.Empty()

	// Test with token auth but missing token
	_ = os.Unsetenv("RADOSGW_OIDC_TOKEN")

	profileConfig := &config.ProfileConfig{
		EndpointURL:         "https://test.example.com",
		RoleArn:             "arn:aws:iam::123456789012:role/TestRole",
		RadosGWOIDCAuthType: "token",
	}

	_, err := GetCredentials("test-profile", profileConfig, awsConfig, false, time.Hour)
	if err == nil {
		t.Error("GetCredentials() with token auth but no token should return error")
	}
	if !strings.Contains(err.Error(), "RADOSGW_OIDC_TOKEN") {
		t.Errorf("GetCredentials() should mention missing RADOSGW_OIDC_TOKEN, got: %v", err)
	}
}

func TestGetCredentials_UnsupportedAuthType(t *testing.T) {
	// Test unsupported authentication type

	awsConfig := ini.Empty()

	profileConfig := &config.ProfileConfig{
		EndpointURL:         "https://test.example.com",
		RoleArn:             "arn:aws:iam::123456789012:role/TestRole",
		RadosGWOIDCProvider: "https://oidc.example.com",
		RadosGWOIDCClientID: "test-client",
		RadosGWOIDCAuthType: "unsupported",
	}

	_, err := GetCredentials("test-profile", profileConfig, awsConfig, false, time.Hour)
	if err == nil {
		t.Error("GetCredentials() with unsupported auth type should return error")
	}
	if !strings.Contains(err.Error(), "unsupported auth type") {
		t.Errorf("GetCredentials() should mention unsupported auth type, got: %v", err)
	}
}

func TestGetCredentials_SSLVerifyParsing(t *testing.T) {
	tests := []struct {
		name         string
		sslVerify    string
		expectSecure bool
	}{
		{
			name:         "default (empty) should be secure",
			sslVerify:    "",
			expectSecure: true,
		},
		{
			name:         "explicit true",
			sslVerify:    "true",
			expectSecure: true,
		},
		{
			name:         "false should be insecure",
			sslVerify:    "false",
			expectSecure: false,
		},
		{
			name:         "0 should be insecure",
			sslVerify:    "0",
			expectSecure: false,
		},
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "expected test response", http.StatusBadRequest)
	}))
	t.Cleanup(server.Close)

	awsConfig := ini.Empty()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profileConfig := &config.ProfileConfig{
				EndpointURL:         server.URL,
				RoleArn:             "arn:aws:iam::123456789012:role/TestRole",
				RadosGWOIDCProvider: server.URL,
				RadosGWOIDCClientID: "test-client",
				RadosGWSSLVerify:    tt.sslVerify,
			}

			_, err := GetCredentials("test-profile", profileConfig, awsConfig, false, time.Hour)
			if err == nil {
				t.Fatal("GetCredentials() expected an error")
			}

			gotCertificateError := strings.Contains(err.Error(), "certificate")
			if gotCertificateError != tt.expectSecure {
				t.Errorf("certificate verification error = %v, want %v; error: %v", gotCertificateError, tt.expectSecure, err)
			}
		})
	}
}

func TestGetCredentials_DefaultAuthType(t *testing.T) {
	var requestedPath string
	var requestedPKCEMethod string
	var requestedCodeChallenge string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			issuer := "http://" + r.Host
			_, _ = fmt.Fprintf(w, `{
				"issuer":%q,
				"device_authorization_endpoint":%q,
				"token_endpoint":%q
			}`, issuer, issuer+"/oauth2/custom/device", issuer+"/oauth2/custom/token")
			return
		}
		requestedPath = r.URL.Path
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm() error = %v", err)
		}
		requestedPKCEMethod = r.Form.Get("code_challenge_method")
		requestedCodeChallenge = r.Form.Get("code_challenge")
		http.Error(w, "expected test response", http.StatusBadRequest)
	}))
	t.Cleanup(server.Close)

	awsConfig := ini.Empty()

	profileConfig := &config.ProfileConfig{
		EndpointURL:         server.URL,
		RoleArn:             "arn:aws:iam::123456789012:role/TestRole",
		RadosGWOIDCProvider: server.URL,
		RadosGWOIDCClientID: "test-client",
	}

	_, err := GetCredentials("test-profile", profileConfig, awsConfig, false, time.Hour)
	if err == nil {
		t.Fatal("GetCredentials() expected an error from the test server")
	}
	if requestedPath != "/oauth2/custom/device" {
		t.Errorf("requested path = %q, want device authorization endpoint", requestedPath)
	}
	if requestedPKCEMethod != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", requestedPKCEMethod)
	}
	if requestedCodeChallenge == "" {
		t.Error("code_challenge is empty")
	}
}

func TestGetCredentials_InvalidPKCEMethod(t *testing.T) {
	profileConfig := &config.ProfileConfig{
		EndpointURL:           "https://storage.example.com",
		RoleArn:               "arn:aws:iam::123456789012:role/TestRole",
		RadosGWOIDCProvider:   "https://oidc.example.com",
		RadosGWOIDCClientID:   "test-client",
		RadosGWOIDCPKCEMethod: "invalid",
	}

	_, err := GetCredentials("test-profile", profileConfig, ini.Empty(), false, time.Hour)
	if err == nil {
		t.Fatal("GetCredentials() expected an error")
	}
	if !strings.Contains(err.Error(), "unsupported PKCE method") {
		t.Errorf("GetCredentials() error = %v, want unsupported PKCE method", err)
	}
}

func TestGetCredentials_DefaultScope(t *testing.T) {
	var requestedScope string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			issuer := "http://" + r.Host
			_, _ = fmt.Fprintf(w, `{
				"issuer":%q,
				"device_authorization_endpoint":%q,
				"token_endpoint":%q
			}`, issuer, issuer+"/oauth2/custom/device", issuer+"/oauth2/custom/token")
			return
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm() error = %v", err)
		}
		requestedScope = r.Form.Get("scope")
		http.Error(w, "expected test response", http.StatusBadRequest)
	}))
	t.Cleanup(server.Close)

	awsConfig := ini.Empty()

	profileConfig := &config.ProfileConfig{
		EndpointURL:         server.URL,
		RoleArn:             "arn:aws:iam::123456789012:role/TestRole",
		RadosGWOIDCProvider: server.URL,
		RadosGWOIDCClientID: "test-client",
	}

	_, err := GetCredentials("test-profile", profileConfig, awsConfig, false, time.Hour)
	if err == nil {
		t.Fatal("GetCredentials() expected an error from the test server")
	}
	if requestedScope != "openid" {
		t.Errorf("scope = %q, want openid", requestedScope)
	}
}

func TestGetCredentials_InheritsEndpointFromNestedSourceProfile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		_, _ = fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?>
<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <AssumedRoleUser>
      <Arn>arn:aws:sts::123456789012:assumed-role/TestRole/test-session</Arn>
      <AssumedRoleId>AROATEST:test-session</AssumedRoleId>
    </AssumedRoleUser>
    <Credentials>
      <AccessKeyId>test-access-key</AccessKeyId>
      <SecretAccessKey>test-secret-key</SecretAccessKey>
      <SessionToken>test-session-token</SessionToken>
      <Expiration>2030-01-01T00:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
  <ResponseMetadata><RequestId>test-request-id</RequestId></ResponseMetadata>
</AssumeRoleWithWebIdentityResponse>`)
	}))
	t.Cleanup(server.Close)
	t.Setenv("RADOSGW_OIDC_TOKEN", "test-token")

	awsConfig, err := ini.Load([]byte(fmt.Sprintf(`[profile base]
endpoint_url = %s
radosgw_oidc_auth_type = token

[profile derived]
source_profile = shared
role_arn = arn:aws:iam::123456789012:role/TestRole
role_session_name = test-session

[profile shared]
source_profile = base
`, server.URL)))
	if err != nil {
		t.Fatalf("ini.Load() error = %v", err)
	}
	profileConfig, err := config.GetProfileConfig("derived", awsConfig)
	if err != nil {
		t.Fatalf("GetProfileConfig() error = %v", err)
	}

	result, err := GetCredentials("derived", profileConfig, awsConfig, false, time.Hour)
	if err != nil {
		t.Fatalf("GetCredentials() error = %v", err)
	}
	if result.EndpointURL != server.URL {
		t.Errorf("EndpointURL = %q, want %q", result.EndpointURL, server.URL)
	}
}

func TestGetCredentials_AuthFlows(t *testing.T) {
	tests := []struct {
		name               string
		authType           string
		resolvedAuthType   string
		wantVerboseMessage string
	}{
		{
			name:               "default device flow",
			resolvedAuthType:   "device",
			wantVerboseMessage: "# Starting device authentication flow",
		},
		{
			name:               "browser flow",
			authType:           "browser",
			resolvedAuthType:   "browser",
			wantVerboseMessage: "# Starting browser authentication flow",
		},
		{
			name:               "token flow",
			authType:           "token",
			resolvedAuthType:   "token",
			wantVerboseMessage: "# Using pre-existing OIDC token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stderr := &bytes.Buffer{}
			dependencies := newTestCredentialDependencies(t, stderr)
			expectedAccessToken := tt.resolvedAuthType + "-token"
			profileConfig := &config.ProfileConfig{
				EndpointURL:           "https://storage.example.com",
				RoleArn:               "arn:aws:iam::123456789012:role/TestRole",
				RadosGWOIDCProvider:   "https://oidc.example.com",
				RadosGWOIDCClientID:   "test-client",
				RadosGWOIDCAuthType:   tt.authType,
				RadosGWOIDCScope:      "openid groups",
				RadosGWOIDCPKCEMethod: "plain",
				RadosGWSSLVerify:      "false",
			}

			switch tt.resolvedAuthType {
			case "device":
				dependencies.authenticateDevice = func(providerURL, clientID, scope, pkceMethod string, sslVerify, verboseMode bool) (string, error) {
					assertAuthenticationArguments(t, providerURL, clientID, scope, pkceMethod, sslVerify, verboseMode)
					return "device-token", nil
				}
			case "browser":
				dependencies.authenticateBrowser = func(providerURL, clientID, scope, pkceMethod string, sslVerify, verboseMode bool) (string, error) {
					assertAuthenticationArguments(t, providerURL, clientID, scope, pkceMethod, sslVerify, verboseMode)
					return "browser-token", nil
				}
			case "token":
				expectedAccessToken = "environment-token"
				dependencies.getenv = func(name string) string {
					if name != "RADOSGW_OIDC_TOKEN" {
						t.Errorf("getenv() name = %q, want RADOSGW_OIDC_TOKEN", name)
					}
					return "environment-token"
				}
			}

			dependencies.assumeRole = func(endpointURL, roleARN, accessToken, sessionName string, sslVerify bool, sessionDuration time.Duration) (*config.AssumeRoleResult, error) {
				if endpointURL != profileConfig.EndpointURL {
					t.Errorf("assumeRole() endpoint = %q, want %q", endpointURL, profileConfig.EndpointURL)
				}
				if roleARN != profileConfig.RoleArn {
					t.Errorf("assumeRole() role ARN = %q, want %q", roleARN, profileConfig.RoleArn)
				}
				if accessToken != expectedAccessToken {
					t.Errorf("assumeRole() access token = %q, want %q", accessToken, expectedAccessToken)
				}
				if sessionName != "radosgw-assume-20300102T030405Z" {
					t.Errorf("assumeRole() session name = %q, want deterministic default", sessionName)
				}
				if sslVerify {
					t.Error("assumeRole() SSL verification = true, want false")
				}
				if sessionDuration != 2*time.Hour {
					t.Errorf("assumeRole() duration = %v, want 2h", sessionDuration)
				}
				return &config.AssumeRoleResult{
					AssumedRoleArn: "arn:aws:sts::123456789012:assumed-role/TestRole/test-session",
					EndpointURL:    endpointURL,
				}, nil
			}

			result, err := getCredentials("test-profile", profileConfig, ini.Empty(), true, 2*time.Hour, dependencies)
			if err != nil {
				t.Fatalf("getCredentials() error = %v", err)
			}
			if result.ProfileName != "test-profile" {
				t.Errorf("ProfileName = %q, want test-profile", result.ProfileName)
			}

			verboseOutput := stderr.String()
			for _, expected := range []string{
				"# Direct role assumption: " + profileConfig.RoleArn,
				"# Using profile: test-profile",
				"# Auth type: " + tt.resolvedAuthType,
				tt.wantVerboseMessage,
				"# Session duration: 7200 seconds (2h)",
				"# Assumed role ARN:",
			} {
				if !strings.Contains(verboseOutput, expected) {
					t.Errorf("verbose output %q does not contain %q", verboseOutput, expected)
				}
			}
			if tt.resolvedAuthType == "token" && strings.Contains(verboseOutput, "# OIDC provider:") {
				t.Errorf("token verbose output unexpectedly contains OIDC provider: %q", verboseOutput)
			}
		})
	}
}

func TestGetCredentials_SourceProfile(t *testing.T) {
	stderr := &bytes.Buffer{}
	dependencies := newTestCredentialDependencies(t, stderr)
	awsConfig := ini.Empty()
	profileConfig := &config.ProfileConfig{
		RoleArn:         "arn:aws:iam::123456789012:role/DerivedRole",
		RoleSessionName: "custom-session",
		SourceProfile:   "base",
	}
	sourceConfig := &config.ProfileConfig{
		EndpointURL:         "https://storage.example.com",
		RadosGWOIDCAuthType: "token",
	}

	dependencies.resolveSourceProfile = func(gotProfile *config.ProfileConfig, gotConfig *ini.File, verboseMode bool) (*config.ProfileConfig, error) {
		if gotProfile != profileConfig || gotConfig != awsConfig || !verboseMode {
			t.Error("resolveSourceProfile() received unexpected arguments")
		}
		return sourceConfig, nil
	}
	dependencies.getenv = func(string) string { return "test-token" }
	dependencies.now = func() time.Time {
		t.Fatal("now() must not be called when a custom session name is configured")
		return time.Time{}
	}
	dependencies.assumeRole = func(endpointURL, roleARN, accessToken, sessionName string, sslVerify bool, sessionDuration time.Duration) (*config.AssumeRoleResult, error) {
		if endpointURL != sourceConfig.EndpointURL || roleARN != profileConfig.RoleArn || accessToken != "test-token" {
			t.Error("assumeRole() received unexpected role parameters")
		}
		if sessionName != profileConfig.RoleSessionName {
			t.Errorf("assumeRole() session name = %q, want %q", sessionName, profileConfig.RoleSessionName)
		}
		if !sslVerify || sessionDuration != time.Hour {
			t.Error("assumeRole() received unexpected transport or duration settings")
		}
		return &config.AssumeRoleResult{}, nil
	}

	result, err := getCredentials("derived", profileConfig, awsConfig, true, time.Hour, dependencies)
	if err != nil {
		t.Fatalf("getCredentials() error = %v", err)
	}
	if result.ProfileName != "derived" {
		t.Errorf("ProfileName = %q, want derived", result.ProfileName)
	}
	for _, expected := range []string{
		"# Role assumption: " + profileConfig.RoleArn,
		"# Source profile: base",
		"# Session name: custom-session",
	} {
		if !strings.Contains(stderr.String(), expected) {
			t.Errorf("verbose output %q does not contain %q", stderr.String(), expected)
		}
	}
}

func TestGetCredentials_DependencyErrors(t *testing.T) {
	tests := []struct {
		name        string
		authType    string
		configure   func(*credentialDependencies)
		wantMessage string
	}{
		{
			name:     "missing token",
			authType: "token",
			configure: func(dependencies *credentialDependencies) {
				dependencies.getenv = func(string) string { return "" }
			},
			wantMessage: "RADOSGW_OIDC_TOKEN",
		},
		{
			name:     "device authentication",
			authType: "device",
			configure: func(dependencies *credentialDependencies) {
				dependencies.authenticateDevice = func(string, string, string, string, bool, bool) (string, error) {
					return "", errors.New("device failure")
				}
			},
			wantMessage: "device authentication failed: device failure",
		},
		{
			name:     "browser authentication",
			authType: "browser",
			configure: func(dependencies *credentialDependencies) {
				dependencies.authenticateBrowser = func(string, string, string, string, bool, bool) (string, error) {
					return "", errors.New("browser failure")
				}
			},
			wantMessage: "browser authentication failed: browser failure",
		},
		{
			name:     "role assumption",
			authType: "token",
			configure: func(dependencies *credentialDependencies) {
				dependencies.getenv = func(string) string { return "test-token" }
				dependencies.assumeRole = func(string, string, string, string, bool, time.Duration) (*config.AssumeRoleResult, error) {
					return nil, errors.New("STS failure")
				}
			},
			wantMessage: "STS failure",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dependencies := newTestCredentialDependencies(t, &bytes.Buffer{})
			profileConfig := &config.ProfileConfig{
				EndpointURL:         "https://storage.example.com",
				RoleArn:             "arn:aws:iam::123456789012:role/TestRole",
				RadosGWOIDCProvider: "https://oidc.example.com",
				RadosGWOIDCClientID: "test-client",
				RadosGWOIDCAuthType: tt.authType,
			}
			tt.configure(&dependencies)

			_, err := getCredentials("test-profile", profileConfig, ini.Empty(), false, time.Hour, dependencies)
			if err == nil {
				t.Fatal("getCredentials() expected an error")
			}
			if !strings.Contains(err.Error(), tt.wantMessage) {
				t.Errorf("getCredentials() error = %q, want it to contain %q", err, tt.wantMessage)
			}
		})
	}
}

func TestGetCredentials_SourceProfileError(t *testing.T) {
	dependencies := newTestCredentialDependencies(t, &bytes.Buffer{})
	dependencies.resolveSourceProfile = func(*config.ProfileConfig, *ini.File, bool) (*config.ProfileConfig, error) {
		return nil, errors.New("source profile failure")
	}
	profileConfig := &config.ProfileConfig{
		RoleArn:       "arn:aws:iam::123456789012:role/TestRole",
		SourceProfile: "base",
	}

	_, err := getCredentials("derived", profileConfig, ini.Empty(), false, time.Hour, dependencies)
	if err == nil || !strings.Contains(err.Error(), "source profile failure") {
		t.Errorf("getCredentials() error = %v, want source profile failure", err)
	}
}

func newTestCredentialDependencies(t *testing.T, stderr *bytes.Buffer) credentialDependencies {
	t.Helper()
	return credentialDependencies{
		stderr: stderr,
		getenv: func(string) string {
			t.Fatal("unexpected getenv() call")
			return ""
		},
		now: func() time.Time {
			return time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
		},
		resolveSourceProfile: func(*config.ProfileConfig, *ini.File, bool) (*config.ProfileConfig, error) {
			t.Fatal("unexpected resolveSourceProfile() call")
			return nil, nil
		},
		authenticateDevice: func(string, string, string, string, bool, bool) (string, error) {
			t.Fatal("unexpected authenticateDevice() call")
			return "", nil
		},
		authenticateBrowser: func(string, string, string, string, bool, bool) (string, error) {
			t.Fatal("unexpected authenticateBrowser() call")
			return "", nil
		},
		assumeRole: func(string, string, string, string, bool, time.Duration) (*config.AssumeRoleResult, error) {
			t.Fatal("unexpected assumeRole() call")
			return nil, nil
		},
	}
}

func assertAuthenticationArguments(t *testing.T, providerURL, clientID, scope, pkceMethod string, sslVerify, verboseMode bool) {
	t.Helper()
	if providerURL != "https://oidc.example.com" {
		t.Errorf("authenticate() provider URL = %q", providerURL)
	}
	if clientID != "test-client" {
		t.Errorf("authenticate() client ID = %q", clientID)
	}
	if scope != "openid groups" {
		t.Errorf("authenticate() scope = %q", scope)
	}
	if pkceMethod != "plain" {
		t.Errorf("authenticate() PKCE method = %q", pkceMethod)
	}
	if sslVerify {
		t.Error("authenticate() SSL verification = true, want false")
	}
	if !verboseMode {
		t.Error("authenticate() verbose mode = false, want true")
	}
}
