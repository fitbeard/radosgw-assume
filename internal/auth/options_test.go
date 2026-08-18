package auth

import "github.com/fitbeard/radosgw-assume/internal/config"

func testOIDCOptions() OIDCOptions {
	return OIDCOptions{
		ProviderURL: "https://oidc.example.com",
		ClientID:    "test-client",
		Scope:       "openid",
		PKCEMethod:  config.PKCEMethodS256,
		SSLVerify:   true,
	}
}
