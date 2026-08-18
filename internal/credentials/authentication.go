package credentials

import (
	"context"
	"fmt"

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
		accessToken, err := dependencies.authenticateDevice(
			ctx,
			resolvedConfig.sourceConfig.RadosGWOIDCProvider,
			resolvedConfig.sourceConfig.RadosGWOIDCClientID,
			resolvedConfig.scope,
			string(resolvedConfig.sourceConfig.RadosGWOIDCPKCEMethod),
			resolvedConfig.sslVerify,
			verboseMode,
		)
		if err != nil {
			return "", fmt.Errorf("device authentication failed: %w", err)
		}
		return accessToken, nil
	case config.AuthTypeBrowser:
		verbosef(dependencies.stderr, verboseMode, "# Starting browser authentication flow\n")
		accessToken, err := dependencies.authenticateBrowser(
			ctx,
			resolvedConfig.sourceConfig.RadosGWOIDCProvider,
			resolvedConfig.sourceConfig.RadosGWOIDCClientID,
			resolvedConfig.scope,
			string(resolvedConfig.sourceConfig.RadosGWOIDCPKCEMethod),
			resolvedConfig.sslVerify,
			verboseMode,
		)
		if err != nil {
			return "", fmt.Errorf("browser authentication failed: %w", err)
		}
		return accessToken, nil
	default:
		return "", fmt.Errorf("unsupported auth type: %s (supported: device, browser, token)", resolvedConfig.authType)
	}
}
