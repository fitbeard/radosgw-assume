package config

import (
	"testing"

	"gopkg.in/ini.v1"
)

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
