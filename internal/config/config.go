package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/ini.v1"
)

type configLoadDependencies struct {
	stderr      io.Writer
	userHomeDir func() (string, error)
	loadINIFile func(string) (*ini.File, error)
}

func newConfigLoadDependencies() configLoadDependencies {
	return configLoadDependencies{
		stderr:      os.Stderr,
		userHomeDir: os.UserHomeDir,
		loadINIFile: func(path string) (*ini.File, error) { return ini.Load(path) },
	}
}

// LoadAWSConfig loads the AWS configuration file from ~/.aws/config
func LoadAWSConfig() (*ini.File, error) {
	return loadAWSConfig(newConfigLoadDependencies())
}

func loadAWSConfig(dependencies configLoadDependencies) (*ini.File, error) {
	homeDir, err := dependencies.userHomeDir()
	if err != nil {
		return nil, fmt.Errorf("could not find home directory: %w", err)
	}

	configPath := filepath.Join(homeDir, ".aws", "config")
	config, err := dependencies.loadINIFile(configPath)
	if err == nil {
		return config, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return ini.Empty(), nil
	}

	return nil, fmt.Errorf("failed to load AWS config: %w", err)
}

// LoadAWSConfigOrEmpty loads the AWS config, returning an empty config on error.
// If verboseMode is true and loading fails, an error message is printed to stderr.
func LoadAWSConfigOrEmpty(verboseMode bool) *ini.File {
	return loadAWSConfigOrEmpty(verboseMode, newConfigLoadDependencies())
}

func loadAWSConfigOrEmpty(verboseMode bool, dependencies configLoadDependencies) *ini.File {
	awsConfig, err := loadAWSConfig(dependencies)
	if err != nil {
		if verboseMode {
			_, _ = fmt.Fprintf(dependencies.stderr, "# Failed to load config file: %v\n", err)
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

		// Direct profiles provide their endpoint locally.
		if section.HasKey("endpoint_url") && (section.HasKey("radosgw_oidc_provider") || section.HasKey("role_arn")) {
			profiles = append(profiles, profileName)
			continue
		}
		// Inherited profiles can obtain the endpoint and OIDC settings through
		// source_profile, but must define the role they assume themselves.
		if !section.HasKey("source_profile") || !section.HasKey("role_arn") {
			continue
		}

		profileConfig := &ProfileConfig{}
		if err := section.MapTo(profileConfig); err != nil {
			continue
		}
		if profileConfig.SourceProfile == "" || profileConfig.RoleArn == "" {
			continue
		}
		resolvedConfig, err := ResolveSourceProfile(profileConfig, awsConfig, false)
		if err != nil {
			continue
		}
		if resolvedConfig.EndpointURL != "" && (resolvedConfig.RadosGWOIDCProvider != "" || resolvedConfig.RoleArn != "") {
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
		if len(availableProfiles) == 0 {
			return nil, fmt.Errorf("profile '%s' not found. No RadosGW profiles configured in ~/.aws/config", profileName)
		}
		return nil, fmt.Errorf("profile '%s' not found. Available RadosGW profiles: %s", profileName, strings.Join(availableProfiles, ", "))
	}

	return profileConfig, nil
}

// ResolveSourceProfile resolves source_profile inheritance
func ResolveSourceProfile(profileConfig *ProfileConfig, awsConfig *ini.File, verboseMode bool) (*ProfileConfig, error) {
	return resolveSourceProfile(profileConfig, awsConfig, verboseMode, nil)
}

func resolveSourceProfile(profileConfig *ProfileConfig, awsConfig *ini.File, verboseMode bool, chain []string) (*ProfileConfig, error) {
	if profileConfig.SourceProfile == "" {
		return profileConfig, nil
	}

	sourceProfile := profileConfig.SourceProfile
	for index, profileName := range chain {
		if profileName == sourceProfile {
			cycle := append(append([]string{}, chain[index:]...), sourceProfile)
			return nil, fmt.Errorf("source_profile cycle detected: %s", strings.Join(cycle, " -> "))
		}
	}
	chain = append(chain, sourceProfile)

	if verboseMode {
		_, _ = fmt.Fprintf(os.Stderr, "# Resolving source profile: %s\n", sourceProfile)
	}
	sourceConfig, err := getProfileConfigForResolution(sourceProfile, awsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve source_profile chain %s: %w", strings.Join(chain, " -> "), err)
	}
	resolvedSourceConfig, err := resolveSourceProfile(sourceConfig, awsConfig, verboseMode, chain)
	if err != nil {
		return nil, err
	}

	return mergeProfileConfigs(resolvedSourceConfig, profileConfig), nil
}

func getProfileConfigForResolution(profileName string, awsConfig *ini.File) (*ProfileConfig, error) {
	configSection := "profile " + profileName
	if profileName == "default" {
		configSection = "default"
	}

	section, err := awsConfig.GetSection(configSection)
	if err != nil {
		return nil, fmt.Errorf("profile '%s' not found in ~/.aws/config", profileName)
	}

	profileConfig := &ProfileConfig{}
	if err := section.MapTo(profileConfig); err != nil {
		return nil, fmt.Errorf("failed to parse profile '%s': %w", profileName, err)
	}
	return profileConfig, nil
}

func mergeProfileConfigs(sourceConfig, profileConfig *ProfileConfig) *ProfileConfig {
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
	if profileConfig.RadosGWOIDCToken != "" {
		mergedConfig.RadosGWOIDCToken = profileConfig.RadosGWOIDCToken
	}
	if profileConfig.RadosGWOIDCScope != "" {
		mergedConfig.RadosGWOIDCScope = profileConfig.RadosGWOIDCScope
	}
	if profileConfig.RadosGWOIDCPKCEMethod != "" {
		mergedConfig.RadosGWOIDCPKCEMethod = profileConfig.RadosGWOIDCPKCEMethod
	}
	if profileConfig.RadosGWSSLVerify != "" {
		mergedConfig.RadosGWSSLVerify = profileConfig.RadosGWSSLVerify
	}
	if profileConfig.RoleArn != "" {
		mergedConfig.RoleArn = profileConfig.RoleArn
	}
	if profileConfig.RoleSessionName != "" {
		mergedConfig.RoleSessionName = profileConfig.RoleSessionName
	}
	mergedConfig.SourceProfile = ""

	return &mergedConfig
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
	if authType := os.Getenv("RADOSGW_OIDC_AUTH_TYPE"); authType != "" {
		profileConfig.RadosGWOIDCAuthType = authType
	}
	if scope := os.Getenv("RADOSGW_OIDC_SCOPE"); scope != "" {
		profileConfig.RadosGWOIDCScope = scope
	}
	if pkceMethod := os.Getenv("RADOSGW_OIDC_PKCE_METHOD"); pkceMethod != "" {
		profileConfig.RadosGWOIDCPKCEMethod = pkceMethod
	}
	if sslVerify := os.Getenv("RADOSGW_SSL_VERIFY"); sslVerify != "" {
		profileConfig.RadosGWSSLVerify = sslVerify
	}
	if roleArn := os.Getenv("RADOSGW_ROLE_ARN"); roleArn != "" {
		profileConfig.RoleArn = roleArn
	}
	if roleSessionName := os.Getenv("RADOSGW_ROLE_SESSION_NAME"); roleSessionName != "" {
		profileConfig.RoleSessionName = roleSessionName
	}

	return profileConfig, nil
}
