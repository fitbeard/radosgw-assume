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
		return nil, fmt.Errorf("profile '%s': missing required 'endpoint_url'. Add endpoint_url to your profile configuration", profileName)
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
		return nil, fmt.Errorf("profile '%s': missing required 'role_arn'. Specify the IAM role ARN to assume", profileName)
	}

	// Determine auth type first
	authType := sourceConfig.RadosGWOIDCAuthType
	if authType == "" {
		authType = "device"
	}

	// Extract required OIDC configuration from source profile (not needed for token auth)
	if authType != "token" {
		sourceProfileName := profileName
		if profileConfig.SourceProfile != "" {
			sourceProfileName = profileConfig.SourceProfile
		}
		if sourceConfig.RadosGWOIDCProvider == "" {
			return nil, fmt.Errorf("profile '%s': missing required 'radosgw_oidc_provider' - specify your OIDC provider URL", sourceProfileName)
		}
		if sourceConfig.RadosGWOIDCClientID == "" {
			return nil, fmt.Errorf("profile '%s': missing required 'radosgw_oidc_client_id' - specify your OIDC client ID", sourceProfileName)
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

	// Determine session name: use custom name as-is or generate timestamp-based default with prefix
	roleSessionName := profileConfig.RoleSessionName
	if roleSessionName == "" {
		roleSessionName = fmt.Sprintf("radosgw-assume-%s", time.Now().UTC().Format("20060102T150405Z"))
	}

	if verboseMode {
		fmt.Fprintf(os.Stderr, "# Assuming role with web identity: %s\n", roleArn)
		fmt.Fprintf(os.Stderr, "# Session name: %s\n", roleSessionName)
	}

	// Use STS to assume the role
	result, err := sts.AssumeRoleWithWebIdentity(profileConfig.EndpointURL, roleArn, accessToken, roleSessionName, sslVerify, sessionDuration)
	if err != nil {
		return nil, err // Error already has context from sts.formatSTSError
	}

	if verboseMode && result.AssumedRoleArn != "" {
		fmt.Fprintf(os.Stderr, "# Assumed role ARN: %s\n", result.AssumedRoleArn)
	}

	// Set profile name for output display
	result.ProfileName = profileName

	return result, nil
}
