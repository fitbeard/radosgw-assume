package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/ini.v1"
)

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
