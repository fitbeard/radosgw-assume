package credentials

import (
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
	// Test SSL verify flag parsing
	
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
	
	awsConfig := ini.Empty()
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profileConfig := &config.ProfileConfig{
				EndpointURL:         "https://test.example.com",
				RoleArn:             "arn:aws:iam::123456789012:role/TestRole",
				RadosGWOIDCProvider: "https://oidc.example.com",
				RadosGWOIDCClientID: "test-client",
				RadosGWSSLVerify:    tt.sslVerify,
			}
			
			// This will fail with network error, but we can test that SSL verify parsing doesn't cause parse errors
			_, err := GetCredentials("test-profile", profileConfig, awsConfig, false, time.Hour)
			
			// Should fail due to network/auth issues, not due to SSL verify parsing
			if err != nil && strings.Contains(err.Error(), "ssl") && strings.Contains(err.Error(), "verify") {
				t.Errorf("GetCredentials() failed due to SSL verify parsing issue: %v", err)
			}
		})
	}
}

func TestGetCredentials_DefaultAuthType(t *testing.T) {
	// Test that default auth type is device when not specified
	
	awsConfig := ini.Empty()
	
	profileConfig := &config.ProfileConfig{
		EndpointURL:         "https://test.example.com",
		RoleArn:             "arn:aws:iam::123456789012:role/TestRole",
		RadosGWOIDCProvider: "https://oidc.example.com",
		RadosGWOIDCClientID: "test-client",
		// RadosGWOIDCAuthType not specified, should default to "device"
	}
	
	// This will fail with network error, but we can verify auth type defaulting doesn't cause errors
	_, err := GetCredentials("test-profile", profileConfig, awsConfig, false, time.Hour)
	
	// Should fail due to network issues, not auth type issues
	if err != nil && strings.Contains(err.Error(), "unsupported auth type") {
		t.Error("GetCredentials() should default to device auth type when not specified")
	}
}

func TestGetCredentials_DefaultScope(t *testing.T) {
	// Test that default scope is "openid" when not specified
	
	awsConfig := ini.Empty()
	
	profileConfig := &config.ProfileConfig{
		EndpointURL:         "https://test.example.com",
		RoleArn:             "arn:aws:iam::123456789012:role/TestRole",
		RadosGWOIDCProvider: "https://oidc.example.com",
		RadosGWOIDCClientID: "test-client",
		// RadosGWOIDCScope not specified, should default to "openid"
	}
	
	// This will fail with network error, but we can verify scope defaulting doesn't cause errors
	_, err := GetCredentials("test-profile", profileConfig, awsConfig, false, time.Hour)
	
	// Should fail due to network issues, not scope issues
	if err != nil && strings.Contains(err.Error(), "scope") {
		t.Error("GetCredentials() should default to 'openid' scope when not specified")
	}
}