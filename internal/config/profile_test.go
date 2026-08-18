package config

import (
	"testing"

	"gopkg.in/ini.v1"
)

func TestGetRadosGWProfiles(t *testing.T) {
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

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profileConfig, err := GetProfileConfig(test.profileName, config)

			if test.wantErr {
				if err == nil {
					t.Errorf("GetProfileConfig() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("GetProfileConfig() unexpected error: %v", err)
				return
			}

			if profileConfig.EndpointURL != test.wantURL {
				t.Errorf("GetProfileConfig() endpoint = %v, want %v", profileConfig.EndpointURL, test.wantURL)
			}
		})
	}
}
