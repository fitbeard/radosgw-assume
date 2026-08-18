package config

import (
	"fmt"
	"strings"

	"gopkg.in/ini.v1"
)

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
		if err := profileConfig.ValidateValues(); err != nil {
			return nil, fmt.Errorf("profile '%s': %w", profileName, err)
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
