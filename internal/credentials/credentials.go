package credentials

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/fitbeard/radosgw-assume/internal/auth"
	"github.com/fitbeard/radosgw-assume/internal/config"
	"github.com/fitbeard/radosgw-assume/internal/sts"
	"github.com/fitbeard/radosgw-assume/pkg/duration"

	"gopkg.in/ini.v1"
)

const (
	defaultAuthType = "device"
	defaultScope    = "openid"
)

type credentialDependencies struct {
	stderr io.Writer
	getenv func(string) string
	now    func() time.Time

	resolveSourceProfile func(*config.ProfileConfig, *ini.File, bool) (*config.ProfileConfig, error)
	authenticateDevice   func(string, string, string, string, bool, bool) (string, error)
	authenticateBrowser  func(string, string, string, string, bool, bool) (string, error)
	assumeRole           func(string, string, string, string, bool, time.Duration) (*config.AssumeRoleResult, error)
}

type resolvedCredentialConfig struct {
	sourceConfig *config.ProfileConfig
	roleARN      string
	authType     string
	scope        string
	sslVerify    bool
}

func newCredentialDependencies() credentialDependencies {
	return credentialDependencies{
		stderr:               os.Stderr,
		getenv:               os.Getenv,
		now:                  time.Now,
		resolveSourceProfile: config.ResolveSourceProfile,
		authenticateDevice:   auth.AuthenticateDeviceFlow,
		authenticateBrowser:  auth.AuthenticateBrowserFlow,
		assumeRole:           sts.AssumeRoleWithWebIdentity,
	}
}

// GetCredentials orchestrates the authentication and role assumption process.
func GetCredentials(profileName string, profileConfig *config.ProfileConfig, awsConfig *ini.File, verboseMode bool, sessionDuration time.Duration) (*config.AssumeRoleResult, error) {
	return GetCredentialsWithOutput(profileName, profileConfig, awsConfig, verboseMode, sessionDuration, os.Stderr)
}

// GetCredentialsWithOutput orchestrates authentication and role assumption,
// writing user interaction and verbose diagnostics to output.
func GetCredentialsWithOutput(profileName string, profileConfig *config.ProfileConfig, awsConfig *ini.File, verboseMode bool, sessionDuration time.Duration, output io.Writer) (*config.AssumeRoleResult, error) {
	dependencies := newCredentialDependencies()
	dependencies.stderr = output
	dependencies.authenticateDevice = func(providerURL, clientID, scope, pkceMethod string, sslVerify, verboseMode bool) (string, error) {
		return auth.AuthenticateDeviceFlowWithOutput(providerURL, clientID, scope, pkceMethod, sslVerify, verboseMode, output)
	}
	dependencies.authenticateBrowser = func(providerURL, clientID, scope, pkceMethod string, sslVerify, verboseMode bool) (string, error) {
		return auth.AuthenticateBrowserFlowWithOutput(providerURL, clientID, scope, pkceMethod, sslVerify, verboseMode, output)
	}
	return getCredentials(profileName, profileConfig, awsConfig, verboseMode, sessionDuration, dependencies)
}

func getCredentials(profileName string, profileConfig *config.ProfileConfig, awsConfig *ini.File, verboseMode bool, sessionDuration time.Duration, dependencies credentialDependencies) (*config.AssumeRoleResult, error) {
	resolvedConfig, err := resolveCredentialConfig(profileName, profileConfig, awsConfig, verboseMode, dependencies)
	if err != nil {
		return nil, err
	}

	printCredentialContext(dependencies.stderr, profileName, resolvedConfig, verboseMode, sessionDuration)

	accessToken, err := authenticate(resolvedConfig, verboseMode, dependencies)
	if err != nil {
		return nil, err
	}

	roleSessionName := profileConfig.RoleSessionName
	if roleSessionName == "" {
		roleSessionName = fmt.Sprintf("radosgw-assume-%s", dependencies.now().UTC().Format("20060102T150405Z"))
	}

	verbosef(dependencies.stderr, verboseMode, "# Assuming role with web identity: %s\n", resolvedConfig.roleARN)
	verbosef(dependencies.stderr, verboseMode, "# Session name: %s\n", roleSessionName)

	result, err := dependencies.assumeRole(
		resolvedConfig.sourceConfig.EndpointURL,
		resolvedConfig.roleARN,
		accessToken,
		roleSessionName,
		resolvedConfig.sslVerify,
		sessionDuration,
	)
	if err != nil {
		return nil, err
	}

	if result.AssumedRoleArn != "" {
		verbosef(dependencies.stderr, verboseMode, "# Assumed role ARN: %s\n", result.AssumedRoleArn)
	}

	result.ProfileName = profileName
	return result, nil
}

func resolveCredentialConfig(profileName string, profileConfig *config.ProfileConfig, awsConfig *ini.File, verboseMode bool, dependencies credentialDependencies) (*resolvedCredentialConfig, error) {
	if profileConfig.RoleArn == "" {
		return nil, fmt.Errorf("profile '%s': missing required 'role_arn'. Specify the IAM role ARN to assume", profileName)
	}

	sourceConfig := profileConfig
	if profileConfig.SourceProfile != "" {
		var err error
		sourceConfig, err = dependencies.resolveSourceProfile(profileConfig, awsConfig, verboseMode)
		if err != nil {
			return nil, err
		}
		verbosef(dependencies.stderr, verboseMode, "# Role assumption: %s\n", profileConfig.RoleArn)
		verbosef(dependencies.stderr, verboseMode, "# Source profile: %s\n", profileConfig.SourceProfile)
	} else {
		verbosef(dependencies.stderr, verboseMode, "# Direct role assumption: %s\n", profileConfig.RoleArn)
	}

	if sourceConfig.EndpointURL == "" {
		return nil, fmt.Errorf("profile '%s': missing required 'endpoint_url'. Add endpoint_url to your profile or its source profile", profileName)
	}

	authType := sourceConfig.RadosGWOIDCAuthType
	if authType == "" {
		authType = defaultAuthType
	}

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

	scope := sourceConfig.RadosGWOIDCScope
	if scope == "" {
		scope = defaultScope
	}

	return &resolvedCredentialConfig{
		sourceConfig: sourceConfig,
		roleARN:      profileConfig.RoleArn,
		authType:     authType,
		scope:        scope,
		sslVerify:    sourceConfig.RadosGWSSLVerify != "false" && sourceConfig.RadosGWSSLVerify != "0",
	}, nil
}

func printCredentialContext(stderr io.Writer, profileName string, resolvedConfig *resolvedCredentialConfig, verboseMode bool, sessionDuration time.Duration) {
	verbosef(stderr, verboseMode, "# Using profile: %s\n", profileName)
	verbosef(stderr, verboseMode, "# RadosGW endpoint: %s\n", resolvedConfig.sourceConfig.EndpointURL)
	if resolvedConfig.authType != "token" {
		verbosef(stderr, verboseMode, "# OIDC provider: %s\n", resolvedConfig.sourceConfig.RadosGWOIDCProvider)
	}
	verbosef(stderr, verboseMode, "# Auth type: %s\n", resolvedConfig.authType)
	verbosef(stderr, verboseMode, "# Session duration: %d seconds (%s)\n", int(sessionDuration.Seconds()), duration.Format(sessionDuration))
}

func authenticate(resolvedConfig *resolvedCredentialConfig, verboseMode bool, dependencies credentialDependencies) (string, error) {
	switch resolvedConfig.authType {
	case "token":
		accessToken := dependencies.getenv("RADOSGW_OIDC_TOKEN")
		if accessToken == "" {
			return "", fmt.Errorf("RADOSGW_OIDC_TOKEN environment variable is required for token auth type")
		}
		verbosef(dependencies.stderr, verboseMode, "# Using pre-existing OIDC token\n")
		return accessToken, nil
	case "device":
		verbosef(dependencies.stderr, verboseMode, "# Starting device authentication flow\n")
		accessToken, err := dependencies.authenticateDevice(
			resolvedConfig.sourceConfig.RadosGWOIDCProvider,
			resolvedConfig.sourceConfig.RadosGWOIDCClientID,
			resolvedConfig.scope,
			resolvedConfig.sourceConfig.RadosGWOIDCPKCEMethod,
			resolvedConfig.sslVerify,
			verboseMode,
		)
		if err != nil {
			return "", fmt.Errorf("device authentication failed: %w", err)
		}
		return accessToken, nil
	case "browser":
		verbosef(dependencies.stderr, verboseMode, "# Starting browser authentication flow\n")
		accessToken, err := dependencies.authenticateBrowser(
			resolvedConfig.sourceConfig.RadosGWOIDCProvider,
			resolvedConfig.sourceConfig.RadosGWOIDCClientID,
			resolvedConfig.scope,
			resolvedConfig.sourceConfig.RadosGWOIDCPKCEMethod,
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

func verbosef(w io.Writer, enabled bool, format string, args ...any) {
	if enabled {
		_, _ = fmt.Fprintf(w, format, args...)
	}
}
