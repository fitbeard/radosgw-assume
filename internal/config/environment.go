package config

import (
	"fmt"
	"os"
)

// GetProfileConfigFromEnv creates a ProfileConfig from environment variables
func GetProfileConfigFromEnv() (*ProfileConfig, error) {
	profileConfig := &ProfileConfig{
		EndpointURL:           os.Getenv("AWS_ENDPOINT_URL"),
		RadosGWOIDCProvider:   os.Getenv("RADOSGW_OIDC_PROVIDER"),
		RadosGWOIDCClientID:   os.Getenv("RADOSGW_OIDC_CLIENT_ID"),
		RadosGWOIDCAuthType:   AuthType(os.Getenv("RADOSGW_OIDC_AUTH_TYPE")),
		RadosGWOIDCScope:      os.Getenv("RADOSGW_OIDC_SCOPE"),
		RadosGWOIDCPKCEMethod: PKCEMethod(os.Getenv("RADOSGW_OIDC_PKCE_METHOD")),
		RadosGWSSLVerify:      SSLVerification(os.Getenv("RADOSGW_SSL_VERIFY")),
		RoleArn:               os.Getenv("RADOSGW_ROLE_ARN"),
		RoleSessionName:       os.Getenv("RADOSGW_ROLE_SESSION_NAME"),
	}
	normalizedConfig, err := profileConfig.Normalize()
	if err != nil {
		return nil, err
	}

	if normalizedConfig.EndpointURL == "" {
		return nil, fmt.Errorf("AWS_ENDPOINT_URL environment variable is required")
	}

	// For token auth type, only token and endpoint are required. Scope and OIDC
	// provider settings are ignored because the token has already been issued.
	if normalizedConfig.RadosGWOIDCAuthType == AuthTypeToken {
		return normalizedConfig, nil
	}

	// For other auth types, check for required OIDC variables
	if normalizedConfig.RadosGWOIDCProvider == "" {
		return nil, fmt.Errorf("RADOSGW_OIDC_PROVIDER environment variable is required (not needed for auth_type=token)")
	}
	if normalizedConfig.RadosGWOIDCClientID == "" {
		return nil, fmt.Errorf("RADOSGW_OIDC_CLIENT_ID environment variable is required (not needed for auth_type=token)")
	}

	return normalizedConfig, nil
}
