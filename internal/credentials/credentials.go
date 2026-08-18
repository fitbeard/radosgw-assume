package credentials

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/fitbeard/radosgw-assume/internal/auth"
	"github.com/fitbeard/radosgw-assume/internal/config"

	"gopkg.in/ini.v1"
)

// GetCredentials orchestrates the authentication and role assumption process.
func GetCredentials(ctx context.Context, profileName string, profileConfig *config.ProfileConfig, awsConfig *ini.File, verboseMode bool, sessionDuration time.Duration) (*config.AssumeRoleResult, error) {
	return GetCredentialsWithOutput(ctx, profileName, profileConfig, awsConfig, verboseMode, sessionDuration, os.Stderr)
}

// GetCredentialsWithOutput orchestrates authentication and role assumption,
// writing user interaction and verbose diagnostics to output.
func GetCredentialsWithOutput(ctx context.Context, profileName string, profileConfig *config.ProfileConfig, awsConfig *ini.File, verboseMode bool, sessionDuration time.Duration, output io.Writer) (*config.AssumeRoleResult, error) {
	dependencies := newCredentialDependencies()
	dependencies.stderr = output
	dependencies.authenticateDevice = func(ctx context.Context, providerURL, clientID, scope, pkceMethod string, sslVerify, verboseMode bool) (string, error) {
		return auth.AuthenticateDeviceFlowWithOutput(ctx, providerURL, clientID, scope, pkceMethod, sslVerify, verboseMode, output)
	}
	dependencies.authenticateBrowser = func(ctx context.Context, providerURL, clientID, scope, pkceMethod string, sslVerify, verboseMode bool) (string, error) {
		return auth.AuthenticateBrowserFlowWithOutput(ctx, providerURL, clientID, scope, pkceMethod, sslVerify, verboseMode, output)
	}
	return getCredentials(ctx, profileName, profileConfig, awsConfig, verboseMode, sessionDuration, dependencies)
}

func getCredentials(ctx context.Context, profileName string, profileConfig *config.ProfileConfig, awsConfig *ini.File, verboseMode bool, sessionDuration time.Duration, dependencies credentialDependencies) (*config.AssumeRoleResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	resolvedConfig, err := resolveCredentialConfig(profileName, profileConfig, awsConfig, verboseMode, dependencies)
	if err != nil {
		return nil, err
	}

	printCredentialContext(dependencies.stderr, profileName, resolvedConfig, verboseMode, sessionDuration)

	accessToken, err := authenticate(ctx, resolvedConfig, verboseMode, dependencies)
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
		ctx,
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
