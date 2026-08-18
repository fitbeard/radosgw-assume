package config

import (
	"fmt"
	"strings"
	"testing"
)

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

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateProfileConfig(test.config)

			if test.wantErr {
				if err == nil {
					t.Errorf("validateProfileConfig() expected error but got none")
					return
				}
				if test.errMsg != "" && !strings.Contains(err.Error(), test.errMsg) {
					t.Errorf("validateProfileConfig() error = %v, want to contain %v", err, test.errMsg)
				}
			} else if err != nil {
				t.Errorf("validateProfileConfig() unexpected error: %v", err)
			}
		})
	}
}

func validateProfileConfig(config *ProfileConfig) error {
	if config.EndpointURL == "" {
		return fmt.Errorf("endpoint_url is required")
	}

	if config.RadosGWOIDCAuthType != "token" && config.RadosGWOIDCProvider == "" {
		return fmt.Errorf("radosgw_oidc_provider is required")
	}

	return nil
}
