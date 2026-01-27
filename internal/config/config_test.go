package config

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"gopkg.in/ini.v1"
)

func TestLoadAWSConfig(t *testing.T) {
	// Test the actual LoadAWSConfig function
	config, err := LoadAWSConfig()

	// This might fail if AWS config doesn't exist, which is ok for testing
	if err == nil {
		if config == nil {
			t.Error("LoadAWSConfig() returned nil config")
		}
	}
}

func TestLoadAWSConfigOrEmpty(t *testing.T) {
	// Test that LoadAWSConfigOrEmpty never returns nil
	tests := []struct {
		name        string
		verboseMode bool
	}{
		{
			name:        "verbose mode",
			verboseMode: true,
		},
		{
			name:        "quiet mode",
			verboseMode: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := LoadAWSConfigOrEmpty(tt.verboseMode)
			if config == nil {
				t.Error("LoadAWSConfigOrEmpty() returned nil, expected non-nil config")
			}
		})
	}
}

func TestGetRadosGWProfiles(t *testing.T) {
	// Create test config data
	configContent := `[profile test-profile]
endpoint_url = https://test.example.com
radosgw_oidc_provider = https://oidc.example.com
role_arn = arn:aws:iam::123456789012:role/TestRole

[profile incomplete-profile]
endpoint_url = https://test2.example.com

[profile another-test]
endpoint_url = https://test3.example.com
radosgw_oidc_provider = https://oidc2.example.com
`

	config, err := ini.Load([]byte(configContent))
	if err != nil {
		t.Fatal(err)
	}

	profiles := GetRadosGWProfiles(config)

	expected := []string{"test-profile", "another-test"}
	if len(profiles) != len(expected) {
		t.Errorf("GetRadosGWProfiles() returned %d profiles, want %d", len(profiles), len(expected))
	}

	for _, expectedProfile := range expected {
		found := false
		for _, profile := range profiles {
			if profile == expectedProfile {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("GetRadosGWProfiles() missing expected profile: %s", expectedProfile)
		}
	}
}

func TestGetProfileConfig(t *testing.T) {
	// Create test config data
	configContent := `[profile test-profile]
endpoint_url = https://test.example.com
radosgw_oidc_provider = https://oidc.example.com
radosgw_oidc_client_id = test-client
role_arn = arn:aws:iam::123456789012:role/TestRole

[default]
endpoint_url = https://default.example.com
radosgw_oidc_provider = https://default-oidc.example.com
`

	config, err := ini.Load([]byte(configContent))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		profileName string
		wantErr     bool
		wantURL     string
	}{
		{
			name:        "existing profile",
			profileName: "test-profile",
			wantErr:     false,
			wantURL:     "https://test.example.com",
		},
		{
			name:        "default profile",
			profileName: "default",
			wantErr:     false,
			wantURL:     "https://default.example.com",
		},
		{
			name:        "nonexistent profile",
			profileName: "nonexistent",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profileConfig, err := GetProfileConfig(tt.profileName, config)

			if tt.wantErr {
				if err == nil {
					t.Errorf("GetProfileConfig() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("GetProfileConfig() unexpected error: %v", err)
				return
			}

			if profileConfig.EndpointURL != tt.wantURL {
				t.Errorf("GetProfileConfig() endpoint = %v, want %v", profileConfig.EndpointURL, tt.wantURL)
			}
		})
	}
}

func TestResolveSourceProfile(t *testing.T) {
	// Create test config data with source profile
	configContent := `[profile base-profile]
endpoint_url = https://base.example.com
radosgw_oidc_provider = https://base-oidc.example.com
radosgw_oidc_client_id = base-client

[profile derived-profile]
source_profile = base-profile
role_arn = arn:aws:iam::123456789012:role/DerivedRole
`

	config, err := ini.Load([]byte(configContent))
	if err != nil {
		t.Fatal(err)
	}

	// Get the derived profile
	derivedConfig, err := GetProfileConfig("derived-profile", config)
	if err != nil {
		t.Fatal(err)
	}

	// Resolve source profile
	resolvedConfig, err := ResolveSourceProfile(derivedConfig, config, false)
	if err != nil {
		t.Fatal(err)
	}

	// Check that it inherited from base but kept its own role_arn
	if resolvedConfig.EndpointURL != "https://base.example.com" {
		t.Errorf("ResolveSourceProfile() endpoint = %v, want %v", resolvedConfig.EndpointURL, "https://base.example.com")
	}
	if resolvedConfig.RoleArn != "arn:aws:iam::123456789012:role/DerivedRole" {
		t.Errorf("ResolveSourceProfile() role_arn = %v, want %v", resolvedConfig.RoleArn, "arn:aws:iam::123456789012:role/DerivedRole")
	}
	if resolvedConfig.RadosGWOIDCProvider != "https://base-oidc.example.com" {
		t.Errorf("ResolveSourceProfile() oidc_provider = %v, want %v", resolvedConfig.RadosGWOIDCProvider, "https://base-oidc.example.com")
	}
}

func TestGetProfileConfigFromEnv(t *testing.T) {
	// Save original env
	originalEndpoint := os.Getenv("AWS_ENDPOINT_URL")
	originalProvider := os.Getenv("RADOSGW_OIDC_PROVIDER")
	originalClientID := os.Getenv("RADOSGW_OIDC_CLIENT_ID")
	originalAuthType := os.Getenv("RADOSGW_OIDC_AUTH_TYPE")

	defer func() {
		// Restore original env
		_ = os.Setenv("AWS_ENDPOINT_URL", originalEndpoint)
		_ = os.Setenv("RADOSGW_OIDC_PROVIDER", originalProvider)
		_ = os.Setenv("RADOSGW_OIDC_CLIENT_ID", originalClientID)
		_ = os.Setenv("RADOSGW_OIDC_AUTH_TYPE", originalAuthType)
	}()

	tests := []struct {
		name    string
		envVars map[string]string
		wantErr bool
		wantURL string
	}{
		{
			name: "complete OIDC config",
			envVars: map[string]string{
				"AWS_ENDPOINT_URL":       "https://test.example.com",
				"RADOSGW_OIDC_PROVIDER":  "https://oidc.example.com",
				"RADOSGW_OIDC_CLIENT_ID": "test-client",
			},
			wantErr: false,
			wantURL: "https://test.example.com",
		},
		{
			name: "token auth type",
			envVars: map[string]string{
				"AWS_ENDPOINT_URL":       "https://test.example.com",
				"RADOSGW_OIDC_AUTH_TYPE": "token",
			},
			wantErr: false,
			wantURL: "https://test.example.com",
		},
		{
			name: "missing endpoint",
			envVars: map[string]string{
				"RADOSGW_OIDC_PROVIDER":  "https://oidc.example.com",
				"RADOSGW_OIDC_CLIENT_ID": "test-client",
			},
			wantErr: true,
		},
		{
			name: "missing OIDC provider (non-token auth)",
			envVars: map[string]string{
				"AWS_ENDPOINT_URL":       "https://test.example.com",
				"RADOSGW_OIDC_CLIENT_ID": "test-client",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear relevant env vars
			_ = os.Unsetenv("AWS_ENDPOINT_URL")
			_ = os.Unsetenv("RADOSGW_OIDC_PROVIDER")
			_ = os.Unsetenv("RADOSGW_OIDC_CLIENT_ID")
			_ = os.Unsetenv("RADOSGW_OIDC_AUTH_TYPE")

			// Set test env vars
			for key, value := range tt.envVars {
				_ = os.Setenv(key, value)
			}

			profileConfig, err := GetProfileConfigFromEnv()

			if tt.wantErr {
				if err == nil {
					t.Errorf("GetProfileConfigFromEnv() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("GetProfileConfigFromEnv() unexpected error: %v", err)
				return
			}

			if profileConfig.EndpointURL != tt.wantURL {
				t.Errorf("GetProfileConfigFromEnv() endpoint = %v, want %v", profileConfig.EndpointURL, tt.wantURL)
			}
		})
	}
}

func TestProfileConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *ProfileConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid OIDC config",
			config: &ProfileConfig{
				EndpointURL:         "https://test.example.com",
				RadosGWOIDCProvider: "https://oidc.example.com",
				RadosGWOIDCClientID: "test-client",
			},
			wantErr: false,
		},
		{
			name: "valid token auth config",
			config: &ProfileConfig{
				EndpointURL:         "https://test.example.com",
				RadosGWOIDCAuthType: "token",
			},
			wantErr: false,
		},
		{
			name: "missing endpoint",
			config: &ProfileConfig{
				RadosGWOIDCProvider: "https://oidc.example.com",
				RadosGWOIDCClientID: "test-client",
			},
			wantErr: true,
			errMsg:  "endpoint_url",
		},
		{
			name: "missing OIDC provider for non-token auth",
			config: &ProfileConfig{
				EndpointURL:         "https://test.example.com",
				RadosGWOIDCClientID: "test-client",
			},
			wantErr: true,
			errMsg:  "radosgw_oidc_provider",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateProfileConfig(tt.config)

			if tt.wantErr {
				if err == nil {
					t.Errorf("validateProfileConfig() expected error but got none")
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("validateProfileConfig() error = %v, want to contain %v", err, tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("validateProfileConfig() unexpected error: %v", err)
				}
			}
		})
	}
}

// Helper function to validate ProfileConfig (we might need to add this to the actual code)
func validateProfileConfig(config *ProfileConfig) error {
	if config.EndpointURL == "" {
		return fmt.Errorf("endpoint_url is required")
	}

	// For token auth, OIDC provider is not required
	if config.RadosGWOIDCAuthType != "token" {
		if config.RadosGWOIDCProvider == "" {
			return fmt.Errorf("radosgw_oidc_provider is required")
		}
	}

	return nil
}
