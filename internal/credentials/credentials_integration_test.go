package credentials

import (
	"context"
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
	awsConfig := ini.Empty()

	profileConfig := &config.ProfileConfig{
		RoleArn: "arn:aws:iam::123456789012:role/TestRole",
	}

	_, err := GetCredentials(t.Context(), "test-profile", profileConfig, awsConfig, false, time.Hour)
	if err == nil {
		t.Error("GetCredentials() with missing endpoint URL should return error")
	}
	if !strings.Contains(err.Error(), "endpoint_url") {
		t.Errorf("GetCredentials() should mention missing endpoint_url, got: %v", err)
	}

	profileConfigNoRole := &config.ProfileConfig{
		EndpointURL: "https://test.example.com",
	}

	_, err = GetCredentials(t.Context(), "test-profile", profileConfigNoRole, awsConfig, false, time.Hour)
	if err == nil {
		t.Error("GetCredentials() with missing role ARN should return error")
	}
	if !strings.Contains(err.Error(), "role_arn") {
		t.Errorf("GetCredentials() should mention missing role_arn, got: %v", err)
	}

	profileConfigNoOIDC := &config.ProfileConfig{
		EndpointURL: "https://test.example.com",
		RoleArn:     "arn:aws:iam::123456789012:role/TestRole",
	}

	_, err = GetCredentials(t.Context(), "test-profile", profileConfigNoOIDC, awsConfig, false, time.Hour)
	if err == nil {
		t.Error("GetCredentials() with missing OIDC provider should return error")
	}
	if !strings.Contains(err.Error(), "radosgw_oidc_provider") {
		t.Errorf("GetCredentials() should mention missing radosgw_oidc_provider, got: %v", err)
	}
}

func TestGetCredentialsHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := GetCredentials(ctx, "test-profile", &config.ProfileConfig{}, ini.Empty(), false, time.Hour)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("GetCredentials() error = %v, want context cancellation", err)
	}
}

func TestGetCredentials_TokenAuth(t *testing.T) {
	originalToken := os.Getenv("RADOSGW_OIDC_TOKEN")
	defer func() { _ = os.Setenv("RADOSGW_OIDC_TOKEN", originalToken) }()

	awsConfig := ini.Empty()
	_ = os.Unsetenv("RADOSGW_OIDC_TOKEN")

	profileConfig := &config.ProfileConfig{
		EndpointURL:         "https://test.example.com",
		RoleArn:             "arn:aws:iam::123456789012:role/TestRole",
		RadosGWOIDCAuthType: "token",
	}

	_, err := GetCredentials(t.Context(), "test-profile", profileConfig, awsConfig, false, time.Hour)
	if err == nil {
		t.Error("GetCredentials() with token auth but no token should return error")
	}
	if !strings.Contains(err.Error(), "RADOSGW_OIDC_TOKEN") {
		t.Errorf("GetCredentials() should mention missing RADOSGW_OIDC_TOKEN, got: %v", err)
	}
}

func TestGetCredentials_UnsupportedAuthType(t *testing.T) {
	awsConfig := ini.Empty()

	profileConfig := &config.ProfileConfig{
		EndpointURL:         "https://test.example.com",
		RoleArn:             "arn:aws:iam::123456789012:role/TestRole",
		RadosGWOIDCProvider: "https://oidc.example.com",
		RadosGWOIDCClientID: "test-client",
		RadosGWOIDCAuthType: "unsupported",
	}

	_, err := GetCredentials(t.Context(), "test-profile", profileConfig, awsConfig, false, time.Hour)
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

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profileConfig := &config.ProfileConfig{
				EndpointURL:         server.URL,
				RoleArn:             "arn:aws:iam::123456789012:role/TestRole",
				RadosGWOIDCProvider: server.URL,
				RadosGWOIDCClientID: "test-client",
				RadosGWSSLVerify:    test.sslVerify,
			}

			_, err := GetCredentials(t.Context(), "test-profile", profileConfig, awsConfig, false, time.Hour)
			if err == nil {
				t.Fatal("GetCredentials() expected an error")
			}

			gotCertificateError := strings.Contains(err.Error(), "certificate")
			if gotCertificateError != test.expectSecure {
				t.Errorf("certificate verification error = %v, want %v; error: %v", gotCertificateError, test.expectSecure, err)
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

	_, err := GetCredentials(t.Context(), "test-profile", profileConfig, awsConfig, false, time.Hour)
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

	_, err := GetCredentials(t.Context(), "test-profile", profileConfig, ini.Empty(), false, time.Hour)
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

	_, err := GetCredentials(t.Context(), "test-profile", profileConfig, awsConfig, false, time.Hour)
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

	result, err := GetCredentials(t.Context(), "derived", profileConfig, awsConfig, false, time.Hour)
	if err != nil {
		t.Fatalf("GetCredentials() error = %v", err)
	}
	if result.EndpointURL != server.URL {
		t.Errorf("EndpointURL = %q, want %q", result.EndpointURL, server.URL)
	}
}
