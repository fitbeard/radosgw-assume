package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/ini.v1"
)

func TestLoadAWSConfig(t *testing.T) {
	t.Run("loads config from home directory", func(t *testing.T) {
		homeDirectory := t.TempDir()
		writeTestAWSConfig(t, homeDirectory, `[profile test-profile]
endpoint_url = https://test.example.com
radosgw_oidc_provider = https://oidc.example.com
`)

		config, err := loadAWSConfig(testConfigLoadDependencies(homeDirectory))
		if err != nil {
			t.Fatalf("loadAWSConfig() error = %v", err)
		}
		section, err := config.GetSection("profile test-profile")
		if err != nil {
			t.Fatalf("loaded config does not contain test profile: %v", err)
		}
		if got := section.Key("endpoint_url").String(); got != "https://test.example.com" {
			t.Errorf("endpoint_url = %q, want https://test.example.com", got)
		}
	})

	t.Run("missing config returns empty config", func(t *testing.T) {
		config, err := loadAWSConfig(testConfigLoadDependencies(t.TempDir()))
		if err != nil {
			t.Fatalf("loadAWSConfig() error = %v", err)
		}
		if config == nil {
			t.Fatal("loadAWSConfig() returned nil config")
		}
		if profiles := GetRadosGWProfiles(config); len(profiles) != 0 {
			t.Errorf("profiles = %v, want empty", profiles)
		}
	})

	for _, test := range []struct {
		name    string
		content string
	}{
		{name: "unclosed section", content: "[profile broken"},
		{name: "prefixed section", content: "i[profile system-prd]"},
	} {
		t.Run(test.name+" returns error", func(t *testing.T) {
			homeDirectory := t.TempDir()
			writeTestAWSConfig(t, homeDirectory, test.content)

			_, err := loadAWSConfig(testConfigLoadDependencies(homeDirectory))
			if err == nil || !strings.Contains(err.Error(), "failed to load AWS config") {
				t.Errorf("loadAWSConfig() error = %v, want malformed config error", err)
			}
		})
	}

	t.Run("home lookup failure returns error", func(t *testing.T) {
		dependencies := testConfigLoadDependencies("")
		dependencies.userHomeDir = func() (string, error) {
			return "", errors.New("home lookup failed")
		}

		_, err := loadAWSConfig(dependencies)
		if err == nil || !strings.Contains(err.Error(), "could not find home directory") {
			t.Errorf("loadAWSConfig() error = %v, want home lookup error", err)
		}
	})

	t.Run("filesystem failure is not treated as missing", func(t *testing.T) {
		homeDirectory := t.TempDir()
		dependencies := testConfigLoadDependencies(homeDirectory)
		var loadedPath string
		dependencies.loadINIFile = func(path string) (*ini.File, error) {
			loadedPath = path
			return nil, os.ErrPermission
		}

		_, err := loadAWSConfig(dependencies)
		if err == nil || !errors.Is(err, os.ErrPermission) {
			t.Errorf("loadAWSConfig() error = %v, want permission error", err)
		}
		wantPath := filepath.Join(homeDirectory, ".aws", "config")
		if loadedPath != wantPath {
			t.Errorf("loaded path = %q, want %q", loadedPath, wantPath)
		}
	})

	t.Run("public loader uses home directory", func(t *testing.T) {
		homeDirectory := t.TempDir()
		t.Setenv("HOME", homeDirectory)
		config, err := LoadAWSConfig()
		if err != nil {
			t.Fatalf("LoadAWSConfig() error = %v", err)
		}
		if config == nil {
			t.Fatal("LoadAWSConfig() returned nil config")
		}
	})
}

func testConfigLoadDependencies(homeDirectory string) configLoadDependencies {
	dependencies := newConfigLoadDependencies()
	dependencies.userHomeDir = func() (string, error) { return homeDirectory, nil }
	return dependencies
}

func writeTestAWSConfig(t *testing.T, homeDirectory, content string) {
	t.Helper()
	configDirectory := filepath.Join(homeDirectory, ".aws")
	if err := os.MkdirAll(configDirectory, 0o700); err != nil {
		t.Fatalf("create test AWS config directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDirectory, "config"), []byte(content), 0o600); err != nil {
		t.Fatalf("write test AWS config: %v", err)
	}
}
