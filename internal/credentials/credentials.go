package credentials

import (
	"fmt"
	"os"
	"time"

	"github.com/fitbeard/radosgw-assume/internal/auth"
	"github.com/fitbeard/radosgw-assume/internal/config"
	"github.com/fitbeard/radosgw-assume/internal/sts"
	"github.com/fitbeard/radosgw-assume/pkg/duration"

	"gopkg.in/ini.v1"
)

// GetCredentials orchestrates the authentication and role assumption process
func GetCredentials(profileName string, profileConfig *config.ProfileConfig, awsConfig *ini.File, verboseMode bool, sessionDuration time.Duration) (*config.AssumeRoleResult, error) {
	// Parse endpoint_url
	if profileConfig.EndpointURL == "" {
		return nil, fmt.Errorf("missing required 'endpoint_url' in profile configuration")
	}

	var sourceConfig *config.ProfileConfig
	var roleArn string
	var err error

	// Handle role assumption
	if profileConfig.RoleArn != "" {
		if profileConfig.SourceProfile != "" {
			// Role assumption with source_profile
			sourceConfig, err = config.ResolveSourceProfile(profileConfig, awsConfig, verboseMode)
			if err != nil {
				return nil, err
			}
			if verboseMode {
				fmt.Fprintf(os.Stderr, "# Role assumption: %s\n", profileConfig.RoleArn)
				fmt.Fprintf(os.Stderr, "# Source profile: %s\n", profileConfig.SourceProfile)
			}
		} else {
			// Direct profile with role_arn
			sourceConfig = profileConfig
			if verboseMode {
				fmt.Fprintf(os.Stderr, "# Direct role assumption: %s\n", profileConfig.RoleArn)
			}
		}
		roleArn = profileConfig.RoleArn
	} else {
		return nil, fmt.Errorf("no role_arn specified in profile configuration")
	}

	// Determine auth type first
	authType := sourceConfig.RadosGWOIDCAuthType
	if authType == "" {
		authType = "device"
	}

	// Extract required OIDC configuration from source profile (not needed for token auth)
	if authType != "token" {
		if sourceConfig.RadosGWOIDCProvider == "" {
			return nil, fmt.Errorf("missing required field 'radosgw_oidc_provider' in source profile configuration")
		}
		if sourceConfig.RadosGWOIDCClientID == "" {
			return nil, fmt.Errorf("missing required field 'radosgw_oidc_client_id' in source profile configuration")
		}
	}

	sslVerify := sourceConfig.RadosGWSSLVerify != "false" && sourceConfig.RadosGWSSLVerify != "0"

	if verboseMode {
		fmt.Fprintf(os.Stderr, "# Using profile: %s\n", profileName)
		fmt.Fprintf(os.Stderr, "# RadosGW endpoint: %s\n", profileConfig.EndpointURL)
		if authType != "token" {
			fmt.Fprintf(os.Stderr, "# OIDC provider: %s\n", sourceConfig.RadosGWOIDCProvider)
		}
		fmt.Fprintf(os.Stderr, "# Auth type: %s\n", authType)
		fmt.Fprintf(os.Stderr, "# Session duration: %d seconds (%s)\n", int(sessionDuration.Seconds()), duration.Format(sessionDuration))
	}

	// Authenticate based on auth type
	var accessToken string

	// Get scope (default to "openid" if not specified)
	scope := sourceConfig.RadosGWOIDCScope
	if scope == "" {
		scope = "openid"
	}

	switch authType {
	case "token":
		// Use token from environment variable
		accessToken = os.Getenv("RADOSGW_OIDC_TOKEN")
		if accessToken == "" {
			return nil, fmt.Errorf("RADOSGW_OIDC_TOKEN environment variable is required for token auth type")
		}
		if verboseMode {
			fmt.Fprintf(os.Stderr, "# Using pre-existing OIDC token\n")
		}
	case "device":
		// Use device flow
		if verboseMode {
			fmt.Fprintf(os.Stderr, "# Starting device authentication flow\n")
		}
		accessToken, err = auth.AuthenticateDeviceFlow(sourceConfig.RadosGWOIDCProvider, sourceConfig.RadosGWOIDCClientID, scope, sslVerify, verboseMode)
		if err != nil {
			return nil, fmt.Errorf("device authentication failed: %w", err)
		}
	case "browser":
		// Use authorization code flow with PKCE
		if verboseMode {
			fmt.Fprintf(os.Stderr, "# Starting browser authentication flow\n")
		}
		accessToken, err = auth.AuthenticateBrowserFlow(sourceConfig.RadosGWOIDCProvider, sourceConfig.RadosGWOIDCClientID, scope, sslVerify, verboseMode)
		if err != nil {
			return nil, fmt.Errorf("browser authentication failed: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported auth type: %s (supported: device, browser, token)", authType)
	}

	if verboseMode {
		fmt.Fprintf(os.Stderr, "# Assuming role with web identity: %s\n", roleArn)
	}

	// Use STS to assume the role
	result, err := sts.AssumeRoleWithWebIdentity(profileConfig.EndpointURL, roleArn, accessToken, profileName, sslVerify, sessionDuration)
	if err != nil {
		return nil, fmt.Errorf("AssumeRoleWithWebIdentity failed: %w", err)
	}

	return result, nil
}
