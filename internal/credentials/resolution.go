package credentials

import (
	"fmt"

	"github.com/fitbeard/radosgw-assume/internal/config"

	"gopkg.in/ini.v1"
)

const (
	defaultAuthType = config.AuthTypeDevice
	defaultScope    = "openid"
)

type resolvedCredentialConfig struct {
	sourceConfig *config.ProfileConfig
	roleARN      string
	authType     config.AuthType
	scope        string
	sslVerify    bool
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

	if authType != config.AuthTypeToken {
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
		sslVerify:    sourceConfig.RadosGWSSLVerify.Enabled(),
	}, nil
}
