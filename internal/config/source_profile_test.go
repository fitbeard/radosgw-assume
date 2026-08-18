package config

import (
	"strings"
	"testing"

	"gopkg.in/ini.v1"
)

func TestResolveSourceProfile(t *testing.T) {
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

	derivedConfig, err := GetProfileConfig("derived-profile", config)
	if err != nil {
		t.Fatal(err)
	}

	resolvedConfig, err := ResolveSourceProfile(derivedConfig, config, false)
	if err != nil {
		t.Fatal(err)
	}

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
