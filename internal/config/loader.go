package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/ini.v1"
)

type configLoadDependencies struct {
	userHomeDir func() (string, error)
	loadINIFile func(string) (*ini.File, error)
}

func newConfigLoadDependencies() configLoadDependencies {
	return configLoadDependencies{
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
