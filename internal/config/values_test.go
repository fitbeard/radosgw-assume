package config

import (
	"strings"
	"testing"

	"gopkg.in/ini.v1"
)

func TestAuthTypeValidate(t *testing.T) {
	for _, test := range []struct {
		name     string
		authType AuthType
		wantErr  bool
	}{
		{name: "unset"},
		{name: "device", authType: AuthTypeDevice},
		{name: "browser", authType: AuthTypeBrowser},
		{name: "token", authType: AuthTypeToken},
		{name: "unsupported", authType: "password", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := test.authType.Validate()
			if (err != nil) != test.wantErr {
				t.Errorf("AuthType(%q).Validate() error = %v, wantErr %v", test.authType, err, test.wantErr)
			}
		})
	}
}

func TestPKCEMethodValidate(t *testing.T) {
	for _, test := range []struct {
		name    string
		method  PKCEMethod
		wantErr bool
	}{
		{name: "unset"},
		{name: "S256", method: PKCEMethodS256},
		{name: "plain", method: PKCEMethodPlain},
		{name: "case sensitive", method: "s256", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := test.method.Validate()
			if (err != nil) != test.wantErr {
				t.Errorf("PKCEMethod(%q).Validate() error = %v, wantErr %v", test.method, err, test.wantErr)
			}
		})
	}
}

func TestSSLVerificationEnabled(t *testing.T) {
	tests := []struct {
		name         string
		verification SSLVerification
		want         bool
	}{
		{name: "unset", want: true},
		{name: "true", verification: "true", want: true},
		{name: "one", verification: "1", want: true},
		{name: "false", verification: "false", want: false},
		{name: "zero", verification: "0", want: false},
		{name: "case sensitive", verification: "FALSE", want: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.verification.Enabled(); got != test.want {
				t.Errorf("SSLVerification(%q).Enabled() = %v, want %v", test.verification, got, test.want)
			}
		})
	}
}

func TestSSLVerificationValidate(t *testing.T) {
	for _, test := range []struct {
		name         string
		verification SSLVerification
		wantErr      bool
	}{
		{name: "unset"},
		{name: "true", verification: SSLVerificationTrue},
		{name: "false", verification: SSLVerificationFalse},
		{name: "one", verification: SSLVerificationOne},
		{name: "zero", verification: SSLVerificationZero},
		{name: "case sensitive", verification: "FALSE", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := test.verification.Validate()
			if (err != nil) != test.wantErr {
				t.Errorf("SSLVerification(%q).Validate() error = %v, wantErr %v", test.verification, err, test.wantErr)
			}
		})
	}
}

func TestProfileConfigNormalize(t *testing.T) {
	original := &ProfileConfig{EndpointURL: "https://storage.example.com"}
	normalized, err := original.Normalize()
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if normalized == original {
		t.Fatal("Normalize() returned the original profile pointer")
	}
	if original.RadosGWOIDCAuthType != "" || original.RadosGWOIDCScope != "" ||
		original.RadosGWOIDCPKCEMethod != "" || original.RadosGWSSLVerify != "" {
		t.Fatalf("Normalize() mutated original profile: %#v", original)
	}
	if normalized.RadosGWOIDCAuthType != AuthTypeDevice {
		t.Errorf("auth type = %q, want %q", normalized.RadosGWOIDCAuthType, AuthTypeDevice)
	}
	if normalized.RadosGWOIDCScope != DefaultOIDCScope {
		t.Errorf("scope = %q, want %q", normalized.RadosGWOIDCScope, DefaultOIDCScope)
	}
	if normalized.RadosGWOIDCPKCEMethod != PKCEMethodS256 {
		t.Errorf("PKCE method = %q, want %q", normalized.RadosGWOIDCPKCEMethod, PKCEMethodS256)
	}
	if normalized.RadosGWSSLVerify != SSLVerificationTrue {
		t.Errorf("SSL verification = %q, want %q", normalized.RadosGWSSLVerify, SSLVerificationTrue)
	}
}

func TestProfileConfigNormalizeTokenDefaults(t *testing.T) {
	normalized, err := (&ProfileConfig{RadosGWOIDCAuthType: AuthTypeToken}).Normalize()
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if normalized.RadosGWOIDCScope != "" || normalized.RadosGWOIDCPKCEMethod != "" {
		t.Errorf("token defaults include unused OIDC values: %#v", normalized)
	}
	if normalized.RadosGWSSLVerify != SSLVerificationTrue {
		t.Errorf("SSL verification = %q, want %q", normalized.RadosGWSSLVerify, SSLVerificationTrue)
	}
}

func TestProfileConfigNormalizeErrors(t *testing.T) {
	for _, test := range []struct {
		name        string
		profile     *ProfileConfig
		wantContain string
	}{
		{name: "missing profile", wantContain: "profile configuration is missing"},
		{name: "auth type", profile: &ProfileConfig{RadosGWOIDCAuthType: "password"}, wantContain: "radosgw_oidc_auth_type"},
		{name: "PKCE method", profile: &ProfileConfig{RadosGWOIDCPKCEMethod: "s256"}, wantContain: "radosgw_oidc_pkce_method"},
		{name: "SSL verification", profile: &ProfileConfig{RadosGWSSLVerify: "yes"}, wantContain: "radosgw_ssl_verify"},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := test.profile.Normalize()
			if err == nil || !strings.Contains(err.Error(), test.wantContain) {
				t.Errorf("Normalize() error = %v, want containing %q", err, test.wantContain)
			}
			if result != nil {
				t.Errorf("Normalize() = %#v, want nil", result)
			}
		})
	}
}

func TestTypedProfileValuesLoadFromINI(t *testing.T) {
	awsConfig, err := ini.Load([]byte(`[profile typed]
endpoint_url = https://storage.example.com
radosgw_oidc_provider = https://oidc.example.com
radosgw_oidc_client_id = test-client
radosgw_oidc_auth_type = browser
radosgw_oidc_pkce_method = plain
radosgw_ssl_verify = false
role_arn = arn:aws:iam::123456789012:role/TestRole
`))
	if err != nil {
		t.Fatalf("ini.Load() error = %v", err)
	}

	profile, err := GetProfileConfig("typed", awsConfig)
	if err != nil {
		t.Fatalf("GetProfileConfig() error = %v", err)
	}
	if profile.RadosGWOIDCAuthType != AuthTypeBrowser {
		t.Errorf("auth type = %q, want %q", profile.RadosGWOIDCAuthType, AuthTypeBrowser)
	}
	if profile.RadosGWOIDCPKCEMethod != PKCEMethodPlain {
		t.Errorf("PKCE method = %q, want %q", profile.RadosGWOIDCPKCEMethod, PKCEMethodPlain)
	}
	if profile.RadosGWSSLVerify != SSLVerification("false") {
		t.Errorf("SSL verification = %q, want false", profile.RadosGWSSLVerify)
	}
}
