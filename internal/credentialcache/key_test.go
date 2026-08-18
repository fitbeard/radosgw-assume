package credentialcache

import (
	"testing"
	"time"

	"github.com/fitbeard/radosgw-assume/internal/config"
)

func TestKey(t *testing.T) {
	profileConfig := testProfileConfig()
	baseKey, err := Key("profile", profileConfig, time.Hour, "")
	if err != nil {
		t.Fatalf("Key() error = %v", err)
	}
	if len(baseKey) != 64 {
		t.Fatalf("Key() length = %d, want 64", len(baseKey))
	}

	tests := []struct {
		name      string
		profile   string
		configure func(*config.ProfileConfig)
		duration  time.Duration
		oidcToken string
	}{
		{name: "profile name", profile: "other", duration: time.Hour},
		{name: "endpoint", profile: "profile", configure: func(profile *config.ProfileConfig) { profile.EndpointURL = "https://other.example.com" }, duration: time.Hour},
		{name: "provider", profile: "profile", configure: func(profile *config.ProfileConfig) { profile.RadosGWOIDCProvider = "https://other-idp.example.com" }, duration: time.Hour},
		{name: "client ID", profile: "profile", configure: func(profile *config.ProfileConfig) { profile.RadosGWOIDCClientID = "other-client" }, duration: time.Hour},
		{name: "auth type", profile: "profile", configure: func(profile *config.ProfileConfig) { profile.RadosGWOIDCAuthType = "browser" }, duration: time.Hour},
		{name: "scope", profile: "profile", configure: func(profile *config.ProfileConfig) { profile.RadosGWOIDCScope = "openid email" }, duration: time.Hour},
		{name: "PKCE", profile: "profile", configure: func(profile *config.ProfileConfig) { profile.RadosGWOIDCPKCEMethod = "plain" }, duration: time.Hour},
		{name: "TLS", profile: "profile", configure: func(profile *config.ProfileConfig) { profile.RadosGWSSLVerify = "false" }, duration: time.Hour},
		{name: "role", profile: "profile", configure: func(profile *config.ProfileConfig) { profile.RoleArn = "arn:other" }, duration: time.Hour},
		{name: "session", profile: "profile", configure: func(profile *config.ProfileConfig) { profile.RoleSessionName = "other-session" }, duration: time.Hour},
		{name: "duration", profile: "profile", duration: 2 * time.Hour},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profile := testProfileConfig()
			if test.configure != nil {
				test.configure(profile)
			}
			key, err := Key(test.profile, profile, test.duration, test.oidcToken)
			if err != nil {
				t.Fatalf("Key() error = %v", err)
			}
			if key == baseKey {
				t.Errorf("Key() = %q, want configuration-specific key", key)
			}
		})
	}
}

func TestKeyUsesTokenIdentityOnlyForTokenAuthentication(t *testing.T) {
	profile := testProfileConfig()
	deviceKey, err := Key("profile", profile, time.Hour, "first-token")
	if err != nil {
		t.Fatalf("Key() error = %v", err)
	}
	otherDeviceKey, err := Key("profile", profile, time.Hour, "second-token")
	if err != nil {
		t.Fatalf("Key() error = %v", err)
	}
	if deviceKey != otherDeviceKey {
		t.Error("device cache key unexpectedly includes an environment token")
	}

	profile.RadosGWOIDCAuthType = "token"
	tokenKey, err := Key("profile", profile, time.Hour, "first-token")
	if err != nil {
		t.Fatalf("Key() error = %v", err)
	}
	otherTokenKey, err := Key("profile", profile, time.Hour, "second-token")
	if err != nil {
		t.Fatalf("Key() error = %v", err)
	}
	if tokenKey == otherTokenKey {
		t.Error("token cache key must distinguish source token identities")
	}
}

func TestKeyNormalizesEquivalentDefaults(t *testing.T) {
	implicit := testProfileConfig()
	implicit.RadosGWOIDCAuthType = ""
	implicit.RadosGWOIDCScope = ""
	implicit.RadosGWOIDCPKCEMethod = ""
	implicit.RadosGWSSLVerify = ""

	explicit := testProfileConfig()
	implicitKey, err := Key("profile", implicit, time.Hour, "")
	if err != nil {
		t.Fatalf("Key() implicit defaults error = %v", err)
	}
	explicitKey, err := Key("profile", explicit, time.Hour, "")
	if err != nil {
		t.Fatalf("Key() explicit defaults error = %v", err)
	}
	if implicitKey != explicitKey {
		t.Errorf("semantically equivalent default keys differ: %q != %q", implicitKey, explicitKey)
	}
}

func TestKeyRejectsMissingConfiguration(t *testing.T) {
	if _, err := Key("profile", nil, time.Hour, ""); err == nil {
		t.Fatal("Key() expected an error")
	}
}
