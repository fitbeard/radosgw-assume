package credentials

import (
	"context"
	"fmt"
	"os"

	"github.com/fitbeard/radosgw-assume/internal/auth"
	"github.com/fitbeard/radosgw-assume/internal/config"
	"github.com/fitbeard/radosgw-assume/internal/sts"
)

// GetCredentials orchestrates the authentication and role assumption process.
func GetCredentials(ctx context.Context, options RequestOptions) (*config.AssumeRoleResult, error) {
	output := options.Output
	if output == nil {
		output = os.Stderr
	}
	options.Output = output

	dependencies := newCredentialDependencies()
	dependencies.stderr = output
	dependencies.authenticateDevice = func(ctx context.Context, options auth.OIDCOptions) (string, error) {
		return auth.AuthenticateDeviceFlowWithOutput(ctx, options, output)
	}
	dependencies.authenticateBrowser = func(ctx context.Context, options auth.OIDCOptions) (string, error) {
		return auth.AuthenticateBrowserFlowWithOutput(ctx, options, output)
	}
	return getCredentials(ctx, options, dependencies)
}

func getCredentials(ctx context.Context, options RequestOptions, dependencies credentialDependencies) (*config.AssumeRoleResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	resolvedConfig, err := resolveCredentialConfig(options.ProfileName, options.ProfileConfig, options.AWSConfig, options.Verbose, dependencies)
	if err != nil {
		return nil, err
	}

	printCredentialContext(dependencies.stderr, options.ProfileName, resolvedConfig, options.Verbose, options.SessionDuration)

	accessToken, err := authenticate(ctx, resolvedConfig, options.Verbose, dependencies)
	if err != nil {
		return nil, err
	}

	roleSessionName := options.ProfileConfig.RoleSessionName
	if roleSessionName == "" {
		roleSessionName = fmt.Sprintf("radosgw-assume-%s", dependencies.now().UTC().Format("20060102T150405Z"))
	}

	verbosef(dependencies.stderr, options.Verbose, "# Assuming role with web identity: %s\n", resolvedConfig.roleARN)
	verbosef(dependencies.stderr, options.Verbose, "# Session name: %s\n", roleSessionName)

	result, err := dependencies.assumeRole(ctx, sts.AssumeRoleOptions{
		EndpointURL:      resolvedConfig.sourceConfig.EndpointURL,
		RoleARN:          resolvedConfig.roleARN,
		WebIdentityToken: accessToken,
		RoleSessionName:  roleSessionName,
		SSLVerify:        resolvedConfig.sslVerify,
		SessionDuration:  options.SessionDuration,
	})
	if err != nil {
		return nil, err
	}

	if result.AssumedRoleArn != "" {
		verbosef(dependencies.stderr, options.Verbose, "# Assumed role ARN: %s\n", result.AssumedRoleArn)
	}

	result.ProfileName = options.ProfileName
	return result, nil
}
