package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/ini.v1"
)

func TestLoadAWSConfig(t *testing.T) {
	t.Run("loads config from home directory", func(t *testing.T) {
		homeDirectory := t.TempDir()
		writeTestAWSConfig(t, homeDirectory, `[profile test-profile]
endpoint_url = https://test.example.com
radosgw_oidc_provider = https://oidc.example.com
`)

		config, err := loadAWSConfig(testConfigLoadDependencies(homeDirectory))
		if err != nil {
			t.Fatalf("loadAWSConfig() error = %v", err)
		}
		section, err := config.GetSection("profile test-profile")
		if err != nil {
			t.Fatalf("loaded config does not contain test profile: %v", err)
		}
		if got := section.Key("endpoint_url").String(); got != "https://test.example.com" {
			t.Errorf("endpoint_url = %q, want https://test.example.com", got)
		}
	})

	t.Run("missing config returns empty config", func(t *testing.T) {
		config, err := loadAWSConfig(testConfigLoadDependencies(t.TempDir()))
		if err != nil {
			t.Fatalf("loadAWSConfig() error = %v", err)
		}
		if config == nil {
			t.Fatal("loadAWSConfig() returned nil config")
		}
		if profiles := GetRadosGWProfiles(config); len(profiles) != 0 {
			t.Errorf("profiles = %v, want empty", profiles)
		}
	})

	for _, test := range []struct {
		name    string
		content string
	}{
		{name: "unclosed section", content: "[profile broken"},
		{name: "prefixed section", content: "i[profile system-prd]"},
	} {
		t.Run(test.name+" returns error", func(t *testing.T) {
			homeDirectory := t.TempDir()
			writeTestAWSConfig(t, homeDirectory, test.content)

			_, err := loadAWSConfig(testConfigLoadDependencies(homeDirectory))
			if err == nil || !strings.Contains(err.Error(), "failed to load AWS config") {
				t.Errorf("loadAWSConfig() error = %v, want malformed config error", err)
			}
		})
	}

	t.Run("home lookup failure returns error", func(t *testing.T) {
		dependencies := testConfigLoadDependencies("")
		dependencies.userHomeDir = func() (string, error) {
			return "", errors.New("home lookup failed")
		}

		_, err := loadAWSConfig(dependencies)
		if err == nil || !strings.Contains(err.Error(), "could not find home directory") {
			t.Errorf("loadAWSConfig() error = %v, want home lookup error", err)
		}
	})

	t.Run("filesystem failure is not treated as missing", func(t *testing.T) {
		homeDirectory := t.TempDir()
		dependencies := testConfigLoadDependencies(homeDirectory)
		var loadedPath string
		dependencies.loadINIFile = func(path string) (*ini.File, error) {
			loadedPath = path
			return nil, os.ErrPermission
		}

		_, err := loadAWSConfig(dependencies)
		if err == nil || !errors.Is(err, os.ErrPermission) {
			t.Errorf("loadAWSConfig() error = %v, want permission error", err)
		}
		wantPath := filepath.Join(homeDirectory, ".aws", "config")
		if loadedPath != wantPath {
			t.Errorf("loaded path = %q, want %q", loadedPath, wantPath)
		}
	})

	t.Run("public loader uses home directory", func(t *testing.T) {
		homeDirectory := t.TempDir()
		t.Setenv("HOME", homeDirectory)
		config, err := LoadAWSConfig()
		if err != nil {
			t.Fatalf("LoadAWSConfig() error = %v", err)
		}
		if config == nil {
			t.Fatal("LoadAWSConfig() returned nil config")
		}
	})
}

func testConfigLoadDependencies(homeDirectory string) configLoadDependencies {
	dependencies := newConfigLoadDependencies()
	dependencies.userHomeDir = func() (string, error) { return homeDirectory, nil }
	return dependencies
}

func writeTestAWSConfig(t *testing.T, homeDirectory, content string) {
	t.Helper()
	configDirectory := filepath.Join(homeDirectory, ".aws")
	if err := os.MkdirAll(configDirectory, 0o700); err != nil {
		t.Fatalf("create test AWS config directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDirectory, "config"), []byte(content), 0o600); err != nil {
		t.Fatalf("write test AWS config: %v", err)
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

func TestGetRadosGWProfilesIncludesInheritedProfiles(t *testing.T) {
	configContent := `[profile base]
endpoint_url = https://base.example.com
radosgw_oidc_auth_type = token

[profile shared]
source_profile = base

[profile inherited]
source_profile = shared
role_arn = arn:aws:iam::123456789012:role/InheritedRole

[profile orphan]
source_profile = missing
role_arn = arn:aws:iam::123456789012:role/OrphanRole

[profile cycle-a]
source_profile = cycle-b
role_arn = arn:aws:iam::123456789012:role/CycleA

[profile cycle-b]
source_profile = cycle-a
role_arn = arn:aws:iam::123456789012:role/CycleB
`

	awsConfig, err := ini.Load([]byte(configContent))
	if err != nil {
		t.Fatalf("ini.Load() error = %v", err)
	}

	profiles := GetRadosGWProfiles(awsConfig)
	if len(profiles) != 1 || profiles[0] != "inherited" {
		t.Errorf("GetRadosGWProfiles() = %v, want [inherited]", profiles)
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
radosgw_oidc_scope = openid
radosgw_oidc_pkce_method = S256

[profile derived-profile]
source_profile = base-profile
role_arn = arn:aws:iam::123456789012:role/DerivedRole
radosgw_oidc_scope = openid custom
radosgw_oidc_pkce_method = plain
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
	if resolvedConfig.RadosGWOIDCScope != "openid custom" {
		t.Errorf("ResolveSourceProfile() oidc_scope = %v, want %v", resolvedConfig.RadosGWOIDCScope, "openid custom")
	}
	if resolvedConfig.RadosGWOIDCPKCEMethod != "plain" {
		t.Errorf("ResolveSourceProfile() oidc_pkce_method = %v, want plain", resolvedConfig.RadosGWOIDCPKCEMethod)
	}
}

func TestResolveNestedSourceProfiles(t *testing.T) {
	configContent := `[profile base]
endpoint_url = https://base.example.com
radosgw_oidc_provider = https://base-oidc.example.com
radosgw_oidc_client_id = base-client
radosgw_oidc_auth_type = device
radosgw_oidc_scope = openid
radosgw_oidc_pkce_method = S256
radosgw_ssl_verify = true
role_session_name = base-session

[profile shared]
source_profile = base
radosgw_oidc_client_id = shared-client
radosgw_oidc_scope = openid groups
radosgw_ssl_verify = false

[profile leaf]
source_profile = shared
role_arn = arn:aws:iam::123456789012:role/LeafRole
radosgw_oidc_auth_type = browser
radosgw_oidc_pkce_method = plain
role_session_name = leaf-session
`

	awsConfig, err := ini.Load([]byte(configContent))
	if err != nil {
		t.Fatalf("ini.Load() error = %v", err)
	}
	leafConfig, err := GetProfileConfig("leaf", awsConfig)
	if err != nil {
		t.Fatalf("GetProfileConfig() error = %v", err)
	}

	resolvedConfig, err := ResolveSourceProfile(leafConfig, awsConfig, false)
	if err != nil {
		t.Fatalf("ResolveSourceProfile() error = %v", err)
	}

	want := &ProfileConfig{
		EndpointURL:           "https://base.example.com",
		RadosGWOIDCProvider:   "https://base-oidc.example.com",
		RadosGWOIDCClientID:   "shared-client",
		RadosGWOIDCAuthType:   "browser",
		RadosGWOIDCScope:      "openid groups",
		RadosGWOIDCPKCEMethod: "plain",
		RadosGWSSLVerify:      "false",
		RoleArn:               "arn:aws:iam::123456789012:role/LeafRole",
		RoleSessionName:       "leaf-session",
	}
	if *resolvedConfig != *want {
		t.Errorf("ResolveSourceProfile() = %#v, want %#v", resolvedConfig, want)
	}
}

func TestResolveSourceProfileErrors(t *testing.T) {
	tests := []struct {
		name        string
		config      string
		profileName string
		wantContain string
	}{
		{
			name: "self reference",
			config: `[profile self]
source_profile = self
role_arn = arn:aws:iam::123456789012:role/Self
`,
			profileName: "self",
			wantContain: "self -> self",
		},
		{
			name: "indirect cycle",
			config: `[profile cycle-a]
source_profile = cycle-b
role_arn = arn:aws:iam::123456789012:role/CycleA

[profile cycle-b]
source_profile = cycle-c

[profile cycle-c]
source_profile = cycle-a
`,
			profileName: "cycle-a",
			wantContain: "cycle-b -> cycle-c -> cycle-a -> cycle-b",
		},
		{
			name: "missing nested source",
			config: `[profile leaf]
source_profile = shared
role_arn = arn:aws:iam::123456789012:role/Leaf

[profile shared]
source_profile = missing
`,
			profileName: "leaf",
			wantContain: "shared -> missing",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			awsConfig, err := ini.Load([]byte(test.config))
			if err != nil {
				t.Fatalf("ini.Load() error = %v", err)
			}
			profileConfig, err := GetProfileConfig(test.profileName, awsConfig)
			if err != nil {
				t.Fatalf("GetProfileConfig() error = %v", err)
			}

			result, err := ResolveSourceProfile(profileConfig, awsConfig, false)
			if err == nil {
				t.Fatal("ResolveSourceProfile() expected an error")
			}
			if result != nil {
				t.Errorf("ResolveSourceProfile() = %#v, want nil", result)
			}
			if !strings.Contains(err.Error(), test.wantContain) {
				t.Errorf("ResolveSourceProfile() error = %v, want to contain %q", err, test.wantContain)
			}
		})
	}
}

func TestResolveDefaultSourceProfile(t *testing.T) {
	awsConfig, err := ini.Load([]byte(`[default]
endpoint_url = https://default.example.com
radosgw_oidc_auth_type = token

[profile leaf]
source_profile = default
role_arn = arn:aws:iam::123456789012:role/Leaf
`))
	if err != nil {
		t.Fatalf("ini.Load() error = %v", err)
	}
	profileConfig, err := GetProfileConfig("leaf", awsConfig)
	if err != nil {
		t.Fatalf("GetProfileConfig() error = %v", err)
	}

	resolvedConfig, err := ResolveSourceProfile(profileConfig, awsConfig, false)
	if err != nil {
		t.Fatalf("ResolveSourceProfile() error = %v", err)
	}
	if resolvedConfig.EndpointURL != "https://default.example.com" {
		t.Errorf("EndpointURL = %q, want https://default.example.com", resolvedConfig.EndpointURL)
	}
}

func TestGetProfileConfigFromEnv(t *testing.T) {
	tests := []struct {
		name            string
		envVars         map[string]string
		wantErr         bool
		wantURL         string
		wantAuthType    string
		wantScope       string
		wantPKCEMethod  string
		wantSSLVerify   string
		wantRoleARN     string
		wantSessionName string
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
			wantErr:      false,
			wantURL:      "https://test.example.com",
			wantAuthType: "token",
		},
		{
			name: "with all optional OIDC values",
			envVars: map[string]string{
				"AWS_ENDPOINT_URL":          "https://test.example.com",
				"RADOSGW_OIDC_PROVIDER":     "https://oidc.example.com",
				"RADOSGW_OIDC_CLIENT_ID":    "test-client",
				"RADOSGW_OIDC_AUTH_TYPE":    "browser",
				"RADOSGW_OIDC_SCOPE":        "openid profile",
				"RADOSGW_OIDC_PKCE_METHOD":  "plain",
				"RADOSGW_SSL_VERIFY":        "false",
				"RADOSGW_ROLE_ARN":          "arn:aws:iam::123456789012:role/TestRole",
				"RADOSGW_ROLE_SESSION_NAME": "custom-session",
			},
			wantURL:         "https://test.example.com",
			wantAuthType:    "browser",
			wantScope:       "openid profile",
			wantPKCEMethod:  "plain",
			wantSSLVerify:   "false",
			wantRoleARN:     "arn:aws:iam::123456789012:role/TestRole",
			wantSessionName: "custom-session",
		},
		{
			name: "with custom session name",
			envVars: map[string]string{
				"AWS_ENDPOINT_URL":          "https://test.example.com",
				"RADOSGW_OIDC_PROVIDER":     "https://oidc.example.com",
				"RADOSGW_OIDC_CLIENT_ID":    "test-client",
				"RADOSGW_ROLE_SESSION_NAME": "my-custom-session",
			},
			wantErr:         false,
			wantURL:         "https://test.example.com",
			wantSessionName: "my-custom-session",
		},
		{
			name: "token auth with custom session name",
			envVars: map[string]string{
				"AWS_ENDPOINT_URL":          "https://test.example.com",
				"RADOSGW_OIDC_AUTH_TYPE":    "token",
				"RADOSGW_SSL_VERIFY":        "0",
				"RADOSGW_ROLE_ARN":          "arn:aws:iam::123456789012:role/TokenRole",
				"RADOSGW_ROLE_SESSION_NAME": "token-session",
			},
			wantErr:         false,
			wantURL:         "https://test.example.com",
			wantAuthType:    "token",
			wantSSLVerify:   "0",
			wantRoleARN:     "arn:aws:iam::123456789012:role/TokenRole",
			wantSessionName: "token-session",
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
		{
			name: "missing OIDC client ID (non-token auth)",
			envVars: map[string]string{
				"AWS_ENDPOINT_URL":      "https://test.example.com",
				"RADOSGW_OIDC_PROVIDER": "https://oidc.example.com",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, key := range []string{
				"AWS_ENDPOINT_URL",
				"RADOSGW_OIDC_PROVIDER",
				"RADOSGW_OIDC_CLIENT_ID",
				"RADOSGW_OIDC_AUTH_TYPE",
				"RADOSGW_OIDC_SCOPE",
				"RADOSGW_OIDC_PKCE_METHOD",
				"RADOSGW_SSL_VERIFY",
				"RADOSGW_ROLE_ARN",
				"RADOSGW_ROLE_SESSION_NAME",
			} {
				t.Setenv(key, "")
			}

			for key, value := range tt.envVars {
				t.Setenv(key, value)
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
			if profileConfig.RadosGWOIDCAuthType != tt.wantAuthType {
				t.Errorf("GetProfileConfigFromEnv() auth_type = %v, want %v", profileConfig.RadosGWOIDCAuthType, tt.wantAuthType)
			}
			if profileConfig.RadosGWOIDCScope != tt.wantScope {
				t.Errorf("GetProfileConfigFromEnv() scope = %v, want %v", profileConfig.RadosGWOIDCScope, tt.wantScope)
			}
			if profileConfig.RadosGWOIDCPKCEMethod != tt.wantPKCEMethod {
				t.Errorf("GetProfileConfigFromEnv() pkce_method = %v, want %v", profileConfig.RadosGWOIDCPKCEMethod, tt.wantPKCEMethod)
			}
			if profileConfig.RadosGWSSLVerify != tt.wantSSLVerify {
				t.Errorf("GetProfileConfigFromEnv() ssl_verify = %v, want %v", profileConfig.RadosGWSSLVerify, tt.wantSSLVerify)
			}
			if profileConfig.RoleArn != tt.wantRoleARN {
				t.Errorf("GetProfileConfigFromEnv() role_arn = %v, want %v", profileConfig.RoleArn, tt.wantRoleARN)
			}
			if profileConfig.RoleSessionName != tt.wantSessionName {
				t.Errorf("GetProfileConfigFromEnv() session_name = %v, want %v", profileConfig.RoleSessionName, tt.wantSessionName)
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
