package config

import (
	"fmt"
	"os"
)

// GetProfileConfigFromEnv creates a ProfileConfig from environment variables
func GetProfileConfigFromEnv() (*ProfileConfig, error) {
	// Check for token auth type first
	authType := AuthType(os.Getenv("RADOSGW_OIDC_AUTH_TYPE"))
	endpointURL := os.Getenv("AWS_ENDPOINT_URL")

	if endpointURL == "" {
		return nil, fmt.Errorf("AWS_ENDPOINT_URL environment variable is required")
	}

	// For token auth type, only token and endpoint are required
	if authType == AuthTypeToken {
		profileConfig := &ProfileConfig{
			EndpointURL:         endpointURL,
			RadosGWOIDCAuthType: AuthTypeToken,
		}

		// Optional environment variables for token auth (scope is ignored as token already has scope)
		if sslVerify := os.Getenv("RADOSGW_SSL_VERIFY"); sslVerify != "" {
			profileConfig.RadosGWSSLVerify = SSLVerification(sslVerify)
		}
		if roleArn := os.Getenv("RADOSGW_ROLE_ARN"); roleArn != "" {
			profileConfig.RoleArn = roleArn
		}
		if roleSessionName := os.Getenv("RADOSGW_ROLE_SESSION_NAME"); roleSessionName != "" {
			profileConfig.RoleSessionName = roleSessionName
		}

		return profileConfig, nil
	}

	// For other auth types, check for required OIDC variables
	providerURL := os.Getenv("RADOSGW_OIDC_PROVIDER")
	clientID := os.Getenv("RADOSGW_OIDC_CLIENT_ID")

	if providerURL == "" {
		return nil, fmt.Errorf("RADOSGW_OIDC_PROVIDER environment variable is required (not needed for auth_type=token)")
	}
	if clientID == "" {
		return nil, fmt.Errorf("RADOSGW_OIDC_CLIENT_ID environment variable is required (not needed for auth_type=token)")
	}

	// Build ProfileConfig from environment variables
	profileConfig := &ProfileConfig{
		EndpointURL:         endpointURL,
		RadosGWOIDCProvider: providerURL,
		RadosGWOIDCClientID: clientID,
	}

	// Optional environment variables
	if authType := AuthType(os.Getenv("RADOSGW_OIDC_AUTH_TYPE")); authType != "" {
		profileConfig.RadosGWOIDCAuthType = authType
	}
	if scope := os.Getenv("RADOSGW_OIDC_SCOPE"); scope != "" {
		profileConfig.RadosGWOIDCScope = scope
	}
	if pkceMethod := PKCEMethod(os.Getenv("RADOSGW_OIDC_PKCE_METHOD")); pkceMethod != "" {
		profileConfig.RadosGWOIDCPKCEMethod = pkceMethod
	}
	if sslVerify := os.Getenv("RADOSGW_SSL_VERIFY"); sslVerify != "" {
		profileConfig.RadosGWSSLVerify = SSLVerification(sslVerify)
	}
	if roleArn := os.Getenv("RADOSGW_ROLE_ARN"); roleArn != "" {
		profileConfig.RoleArn = roleArn
	}
	if roleSessionName := os.Getenv("RADOSGW_ROLE_SESSION_NAME"); roleSessionName != "" {
		profileConfig.RoleSessionName = roleSessionName
	}

	return profileConfig, nil
}
