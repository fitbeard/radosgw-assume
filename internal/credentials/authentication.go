package credentials

import (
	"context"
	"fmt"

	"github.com/fitbeard/radosgw-assume/internal/auth"
	"github.com/fitbeard/radosgw-assume/internal/config"
)

func authenticate(ctx context.Context, resolvedConfig *resolvedCredentialConfig, verboseMode bool, dependencies credentialDependencies) (string, error) {
	switch resolvedConfig.authType {
	case config.AuthTypeToken:
		accessToken := dependencies.getenv("RADOSGW_OIDC_TOKEN")
		if accessToken == "" {
			return "", fmt.Errorf("RADOSGW_OIDC_TOKEN environment variable is required for token auth type")
		}
		verbosef(dependencies.stderr, verboseMode, "# Using pre-existing OIDC token\n")
		return accessToken, nil
	case config.AuthTypeDevice:
		verbosef(dependencies.stderr, verboseMode, "# Starting device authentication flow\n")
		accessToken, err := dependencies.authenticateDevice(ctx, oidcOptions(resolvedConfig, verboseMode))
		if err != nil {
			return "", fmt.Errorf("device authentication failed: %w", err)
		}
		return accessToken, nil
	case config.AuthTypeBrowser:
		verbosef(dependencies.stderr, verboseMode, "# Starting browser authentication flow\n")
		accessToken, err := dependencies.authenticateBrowser(ctx, oidcOptions(resolvedConfig, verboseMode))
		if err != nil {
			return "", fmt.Errorf("browser authentication failed: %w", err)
		}
		return accessToken, nil
	default:
		return "", fmt.Errorf("unsupported auth type: %s (supported: device, browser, token)", resolvedConfig.authType)
	}
}

func oidcOptions(resolvedConfig *resolvedCredentialConfig, verboseMode bool) auth.OIDCOptions {
	return auth.OIDCOptions{
		ProviderURL: resolvedConfig.sourceConfig.RadosGWOIDCProvider,
		ClientID:    resolvedConfig.sourceConfig.RadosGWOIDCClientID,
		Scope:       resolvedConfig.scope,
		PKCEMethod:  resolvedConfig.sourceConfig.RadosGWOIDCPKCEMethod,
		SSLVerify:   resolvedConfig.sslVerify,
		Verbose:     verboseMode,
	}
}
