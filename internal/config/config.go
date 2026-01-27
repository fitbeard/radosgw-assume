package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/ini.v1"
)

// LoadAWSConfig loads the AWS configuration file from ~/.aws/config
func LoadAWSConfig() (*ini.File, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("could not find home directory: %w", err)
	}

	configPath := filepath.Join(homeDir, ".aws", "config")

	config := ini.Empty()

	if _, err := os.Stat(configPath); err == nil {
		config, err = ini.Load(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load AWS config: %w", err)
		}
	}

	return config, nil
}

// LoadAWSConfigOrEmpty loads the AWS config, returning an empty config on error.
// If verboseMode is true and loading fails, an error message is printed to stderr.
func LoadAWSConfigOrEmpty(verboseMode bool) *ini.File {
	awsConfig, err := LoadAWSConfig()
	if err != nil {
		if verboseMode {
			fmt.Fprintf(os.Stderr, "# Failed to load config file: %v\n", err)
		}
		return ini.Empty()
	}
	return awsConfig
}

// GetRadosGWProfiles returns a list of profiles that have RadosGW-specific configuration
func GetRadosGWProfiles(awsConfig *ini.File) []string {
	var profiles []string

	for _, section := range awsConfig.Sections() {
		sectionName := section.Name()
		if sectionName == "DEFAULT" || sectionName == ini.DefaultSection {
			continue
		}

		// Check if this is a profile section
		profileName := sectionName
		if strings.HasPrefix(sectionName, "profile ") {
			profileName = strings.TrimPrefix(sectionName, "profile ")
		}

		// Check if it has RadosGW-specific keys
		if section.HasKey("endpoint_url") && (section.HasKey("radosgw_oidc_provider") || section.HasKey("role_arn")) {
			profiles = append(profiles, profileName)
		}
	}

	return profiles
}

// GetProfileConfig retrieves configuration for a specific profile
func GetProfileConfig(profileName string, awsConfig *ini.File) (*ProfileConfig, error) {
	var configSection string

	if profileName == "default" {
		configSection = "default"
	} else {
		configSection = "profile " + profileName
	}

	profileConfig := &ProfileConfig{}

	// Load from config file
	if sec, err := awsConfig.GetSection(configSection); err == nil {
		err = sec.MapTo(profileConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to parse profile config: %w", err)
		}
	} else {
		availableProfiles := GetRadosGWProfiles(awsConfig)
		return nil, fmt.Errorf("profile '%s' not found in ~/.aws/config. Available profiles: %v", profileName, availableProfiles)
	}

	return profileConfig, nil
}

// ResolveSourceProfile resolves source_profile inheritance
func ResolveSourceProfile(profileConfig *ProfileConfig, awsConfig *ini.File, verboseMode bool) (*ProfileConfig, error) {
	if profileConfig.SourceProfile == "" {
		return profileConfig, nil
	}

	if verboseMode {
		fmt.Fprintf(os.Stderr, "# Resolving source profile: %s\n", profileConfig.SourceProfile)
	}
	sourceConfig, err := GetProfileConfig(profileConfig.SourceProfile, awsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve source profile '%s': %w", profileConfig.SourceProfile, err)
	}

	// Merge configs: source config as base, current profile overrides
	mergedConfig := *sourceConfig

	// Override with current profile values (non-empty values take precedence)
	if profileConfig.EndpointURL != "" {
		mergedConfig.EndpointURL = profileConfig.EndpointURL
	}
	if profileConfig.RadosGWOIDCProvider != "" {
		mergedConfig.RadosGWOIDCProvider = profileConfig.RadosGWOIDCProvider
	}
	if profileConfig.RadosGWOIDCClientID != "" {
		mergedConfig.RadosGWOIDCClientID = profileConfig.RadosGWOIDCClientID
	}
	if profileConfig.RadosGWOIDCAuthType != "" {
		mergedConfig.RadosGWOIDCAuthType = profileConfig.RadosGWOIDCAuthType
	}
	if profileConfig.RadosGWSSLVerify != "" {
		mergedConfig.RadosGWSSLVerify = profileConfig.RadosGWSSLVerify
	}
	if profileConfig.RoleArn != "" {
		mergedConfig.RoleArn = profileConfig.RoleArn
	}

	return &mergedConfig, nil
}

// GetProfileConfigFromEnv creates a ProfileConfig from environment variables
func GetProfileConfigFromEnv() (*ProfileConfig, error) {
	// Check for token auth type first
	authType := os.Getenv("RADOSGW_OIDC_AUTH_TYPE")
	endpointURL := os.Getenv("AWS_ENDPOINT_URL")

	if endpointURL == "" {
		return nil, fmt.Errorf("AWS_ENDPOINT_URL environment variable is required")
	}

	// For token auth type, only token and endpoint are required
	if authType == "token" {
		profileConfig := &ProfileConfig{
			EndpointURL:         endpointURL,
			RadosGWOIDCAuthType: "token",
		}

		// Optional environment variables for token auth (scope is ignored as token already has scope)
		if sslVerify := os.Getenv("RADOSGW_SSL_VERIFY"); sslVerify != "" {
			profileConfig.RadosGWSSLVerify = sslVerify
		}
		if roleArn := os.Getenv("RADOSGW_ROLE_ARN"); roleArn != "" {
			profileConfig.RoleArn = roleArn
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
	if authType := os.Getenv("RADOSGW_OIDC_AUTH_TYPE"); authType != "" {
		profileConfig.RadosGWOIDCAuthType = authType
	}
	if scope := os.Getenv("RADOSGW_OIDC_SCOPE"); scope != "" {
		profileConfig.RadosGWOIDCScope = scope
	}
	if sslVerify := os.Getenv("RADOSGW_SSL_VERIFY"); sslVerify != "" {
		profileConfig.RadosGWSSLVerify = sslVerify
	}
	if roleArn := os.Getenv("RADOSGW_ROLE_ARN"); roleArn != "" {
		profileConfig.RoleArn = roleArn
	}

	return profileConfig, nil
}
