package config

import "testing"

func TestGetProfileConfigFromEnv(t *testing.T) {
	tests := []struct {
		name            string
		envVars         map[string]string
		wantErr         bool
		wantURL         string
		wantAuthType    AuthType
		wantScope       string
		wantPKCEMethod  PKCEMethod
		wantSSLVerify   SSLVerification
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

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
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

			for key, value := range test.envVars {
				t.Setenv(key, value)
			}

			profileConfig, err := GetProfileConfigFromEnv()

			if test.wantErr {
				if err == nil {
					t.Errorf("GetProfileConfigFromEnv() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("GetProfileConfigFromEnv() unexpected error: %v", err)
				return
			}

			if profileConfig.EndpointURL != test.wantURL {
				t.Errorf("GetProfileConfigFromEnv() endpoint = %v, want %v", profileConfig.EndpointURL, test.wantURL)
			}
			if profileConfig.RadosGWOIDCAuthType != test.wantAuthType {
				t.Errorf("GetProfileConfigFromEnv() auth_type = %v, want %v", profileConfig.RadosGWOIDCAuthType, test.wantAuthType)
			}
			if profileConfig.RadosGWOIDCScope != test.wantScope {
				t.Errorf("GetProfileConfigFromEnv() scope = %v, want %v", profileConfig.RadosGWOIDCScope, test.wantScope)
			}
			if profileConfig.RadosGWOIDCPKCEMethod != test.wantPKCEMethod {
				t.Errorf("GetProfileConfigFromEnv() pkce_method = %v, want %v", profileConfig.RadosGWOIDCPKCEMethod, test.wantPKCEMethod)
			}
			if profileConfig.RadosGWSSLVerify != test.wantSSLVerify {
				t.Errorf("GetProfileConfigFromEnv() ssl_verify = %v, want %v", profileConfig.RadosGWSSLVerify, test.wantSSLVerify)
			}
			if profileConfig.RoleArn != test.wantRoleARN {
				t.Errorf("GetProfileConfigFromEnv() role_arn = %v, want %v", profileConfig.RoleArn, test.wantRoleARN)
			}
			if profileConfig.RoleSessionName != test.wantSessionName {
				t.Errorf("GetProfileConfigFromEnv() session_name = %v, want %v", profileConfig.RoleSessionName, test.wantSessionName)
			}
		})
	}
}
