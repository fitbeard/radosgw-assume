package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/fitbeard/radosgw-assume/internal/config"

	"gopkg.in/ini.v1"
)

func TestParseCLIArguments(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want cliOptions
	}{
		{
			name: "defaults",
			want: cliOptions{sessionDuration: time.Hour},
		},
		{
			name: "all run options",
			args: []string{"profile", "--verbose", "--env", "--duration", "2h", "--session", "test-session"},
			want: cliOptions{
				profileName:     "profile",
				verbose:         true,
				useEnv:          true,
				sessionDuration: 2 * time.Hour,
				sessionName:     "test-session",
			},
		},
		{
			name: "short options",
			args: []string{"-v", "-e", "-d", "3600", "-s", "test-session"},
			want: cliOptions{
				verbose:         true,
				useEnv:          true,
				sessionDuration: time.Hour,
				sessionName:     "test-session",
			},
		},
		{
			name: "help",
			args: []string{"--help"},
			want: cliOptions{action: actionHelp, sessionDuration: time.Hour},
		},
		{
			name: "version",
			args: []string{"version"},
			want: cliOptions{action: actionVersion, sessionDuration: time.Hour},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCLIArguments("radosgw-assume", tt.args)
			if err != nil {
				t.Fatalf("parseCLIArguments() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("parseCLIArguments() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseCLIArgumentsErrors(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantMessage string
	}{
		{name: "duration value missing", args: []string{"--duration"}, wantMessage: "Duration flag requires a value\nUsage: custom-name -d 1h [profile]"},
		{name: "duration malformed", args: []string{"--duration", "tomorrow"}, wantMessage: "Invalid duration 'tomorrow'"},
		{name: "duration too short", args: []string{"--duration", "1m"}, wantMessage: "duration cannot be less than 15 minutes"},
		{name: "session value missing", args: []string{"--session"}, wantMessage: "Session name flag requires a value\nUsage: custom-name -s my-session [profile]"},
		{name: "session invalid", args: []string{"--session", "not_valid"}, wantMessage: "Invalid session name 'not_valid'"},
		{name: "unknown flag", args: []string{"--unknown"}, wantMessage: "Unknown flag '--unknown'"},
		{name: "multiple profiles", args: []string{"first", "second"}, wantMessage: "Multiple profile names specified"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseCLIArguments("custom-name", tt.args)
			if err == nil {
				t.Fatal("parseCLIArguments() expected an error")
			}
			if !strings.Contains(err.Error(), tt.wantMessage) {
				t.Errorf("parseCLIArguments() error = %q, want it to contain %q", err, tt.wantMessage)
			}
		})
	}
}

func TestCLIRunnerInformationalActions(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantOutput string
	}{
		{name: "help", args: []string{"--help"}, wantOutput: "Usage: radosgw-assume"},
		{name: "version", args: []string{"version"}, wantOutput: "Version "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout := &bytes.Buffer{}
			stderr := &bytes.Buffer{}
			runner := newCLIRunner(stdout, stderr)
			if exitCode := runner.run("radosgw-assume", tt.args); exitCode != 0 {
				t.Fatalf("run() exit code = %d, want 0; stderr: %s", exitCode, stderr.String())
			}
			if !strings.Contains(stdout.String(), tt.wantOutput) {
				t.Errorf("run() stdout = %q, want it to contain %q", stdout.String(), tt.wantOutput)
			}
			if stderr.Len() != 0 {
				t.Errorf("run() stderr = %q, want empty", stderr.String())
			}
		})
	}
}

func TestCLIRunnerNamedProfile(t *testing.T) {
	runner, stdout, stderr := newTestCLIRunner(t)
	awsConfig := ini.Empty()
	profileConfig := &config.ProfileConfig{RoleSessionName: "config-session"}

	runner.loadAWSConfig = func() (*ini.File, error) {
		return awsConfig, nil
	}
	runner.getProfile = func(profileName string, gotConfig *ini.File) (*config.ProfileConfig, error) {
		if profileName != "test-profile" {
			t.Errorf("getProfile() name = %q, want test-profile", profileName)
		}
		if gotConfig != awsConfig {
			t.Error("getProfile() received a different AWS config")
		}
		return profileConfig, nil
	}
	runner.getCredentials = func(profileName string, gotProfile *config.ProfileConfig, gotConfig *ini.File, verbose bool, sessionDuration time.Duration) (*config.AssumeRoleResult, error) {
		if profileName != "test-profile" {
			t.Errorf("getCredentials() profile = %q, want test-profile", profileName)
		}
		if gotProfile != profileConfig || gotConfig != awsConfig {
			t.Error("getCredentials() received unexpected configuration")
		}
		if !verbose {
			t.Error("getCredentials() verbose = false, want true")
		}
		if sessionDuration != 2*time.Hour {
			t.Errorf("getCredentials() duration = %v, want 2h", sessionDuration)
		}
		if gotProfile.RoleSessionName != "cli-session" {
			t.Errorf("session name = %q, want CLI override", gotProfile.RoleSessionName)
		}
		return testAssumeRoleResult("test-profile"), nil
	}

	exitCode := runner.run("radosgw-assume", []string{"--verbose", "--duration", "2h", "--session", "cli-session", "test-profile"})
	if exitCode != 0 {
		t.Fatalf("run() exit code = %d, want 0; stderr: %s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "export AWS_PROFILE='test-profile'") {
		t.Errorf("run() stdout = %q, want profile export", stdout.String())
	}
	if !strings.Contains(stderr.String(), "# Credentials exported for profile: test-profile") {
		t.Errorf("run() stderr = %q, want verbose credential hint", stderr.String())
	}
}

func TestCLIRunnerEnvironmentConfiguration(t *testing.T) {
	runner, stdout, stderr := newTestCLIRunner(t)
	profileConfig := &config.ProfileConfig{}
	wantVerbose := false

	runner.loadEnvConfig = func() (*config.ProfileConfig, error) {
		return profileConfig, nil
	}
	runner.getCredentials = func(profileName string, gotProfile *config.ProfileConfig, awsConfig *ini.File, verbose bool, sessionDuration time.Duration) (*config.AssumeRoleResult, error) {
		if profileName != "env" || gotProfile != profileConfig || awsConfig != nil {
			t.Error("getCredentials() received unexpected environment configuration")
		}
		if verbose != wantVerbose {
			t.Errorf("getCredentials() verbose = %v, want %v", verbose, wantVerbose)
		}
		if sessionDuration != time.Hour {
			t.Errorf("getCredentials() duration = %v, want 1h", sessionDuration)
		}
		return testAssumeRoleResult("env"), nil
	}

	if exitCode := runner.run("radosgw-assume", []string{"--env"}); exitCode != 0 {
		t.Fatalf("run() exit code = %d, want 0; stderr: %s", exitCode, stderr.String())
	}
	if strings.Contains(stdout.String(), "AWS_PROFILE") {
		t.Errorf("run() stdout = %q, must not export a synthetic environment profile", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("run() stderr = %q, want empty", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	wantVerbose = true
	if exitCode := runner.run("radosgw-assume", []string{"--env", "--verbose"}); exitCode != 0 {
		t.Fatalf("verbose run() exit code = %d, want 0; stderr: %s", exitCode, stderr.String())
	}
	if !strings.Contains(stderr.String(), "# Using configuration from environment variables") {
		t.Errorf("verbose run() stderr = %q, want environment configuration message", stderr.String())
	}
}

func TestCLIRunnerInteractiveProfile(t *testing.T) {
	runner, _, stderr := newTestCLIRunner(t)
	awsConfig := ini.Empty()
	profileConfig := &config.ProfileConfig{}

	runner.loadAWSConfig = func() (*ini.File, error) { return awsConfig, nil }
	runner.getProfiles = func(gotConfig *ini.File) []string {
		if gotConfig != awsConfig {
			t.Error("getProfiles() received a different AWS config")
		}
		return []string{"first", "selected"}
	}
	runner.selectProfile = func(profiles []string) (string, error) {
		if strings.Join(profiles, ",") != "first,selected" {
			t.Errorf("selectProfile() profiles = %v", profiles)
		}
		return "selected", nil
	}
	runner.getProfile = func(profileName string, _ *ini.File) (*config.ProfileConfig, error) {
		if profileName != "selected" {
			t.Errorf("getProfile() name = %q, want selected", profileName)
		}
		return profileConfig, nil
	}
	runner.getCredentials = func(profileName string, _ *config.ProfileConfig, _ *ini.File, _ bool, _ time.Duration) (*config.AssumeRoleResult, error) {
		return testAssumeRoleResult(profileName), nil
	}

	if exitCode := runner.run("radosgw-assume", nil); exitCode != 0 {
		t.Fatalf("run() exit code = %d, want 0; stderr: %s", exitCode, stderr.String())
	}
}

func TestCLIRunnerFailures(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		configure   func(*cliRunner)
		wantMessage string
	}{
		{
			name:        "argument parsing",
			args:        []string{"--unknown"},
			configure:   func(_ *cliRunner) {},
			wantMessage: "Error: Unknown flag '--unknown'",
		},
		{
			name: "environment config",
			args: []string{"--env"},
			configure: func(r *cliRunner) {
				r.loadEnvConfig = func() (*config.ProfileConfig, error) { return nil, errors.New("env failure") }
			},
			wantMessage: "Error loading configuration from environment variables: env failure",
		},
		{
			name: "no interactive profiles after config failure",
			args: []string{"--verbose"},
			configure: func(r *cliRunner) {
				r.loadAWSConfig = func() (*ini.File, error) { return nil, errors.New("config failure") }
				r.getProfiles = func(*ini.File) []string { return nil }
			},
			wantMessage: "# Failed to load config file: config failure\nNo RadosGW profiles found",
		},
		{
			name: "interactive selector",
			configure: func(r *cliRunner) {
				r.loadAWSConfig = func() (*ini.File, error) { return ini.Empty(), nil }
				r.getProfiles = func(*ini.File) []string { return []string{"profile"} }
				r.selectProfile = func([]string) (string, error) { return "", errors.New("selection failure") }
			},
			wantMessage: "Error: selection failure",
		},
		{
			name: "named profile",
			args: []string{"missing"},
			configure: func(r *cliRunner) {
				r.loadAWSConfig = func() (*ini.File, error) { return ini.Empty(), nil }
				r.getProfile = func(string, *ini.File) (*config.ProfileConfig, error) { return nil, errors.New("profile failure") }
			},
			wantMessage: "Error: profile failure",
		},
		{
			name: "credential acquisition",
			args: []string{"profile"},
			configure: func(r *cliRunner) {
				r.loadAWSConfig = func() (*ini.File, error) { return ini.Empty(), nil }
				r.getProfile = func(string, *ini.File) (*config.ProfileConfig, error) { return &config.ProfileConfig{}, nil }
				r.getCredentials = func(string, *config.ProfileConfig, *ini.File, bool, time.Duration) (*config.AssumeRoleResult, error) {
					return nil, errors.New("credential failure")
				}
			},
			wantMessage: "Error: credential failure",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner, stdout, stderr := newTestCLIRunner(t)
			tt.configure(runner)
			if exitCode := runner.run("radosgw-assume", tt.args); exitCode != 1 {
				t.Errorf("run() exit code = %d, want 1", exitCode)
			}
			if stdout.Len() != 0 {
				t.Errorf("run() stdout = %q, want empty", stdout.String())
			}
			if !strings.Contains(stderr.String(), tt.wantMessage) {
				t.Errorf("run() stderr = %q, want it to contain %q", stderr.String(), tt.wantMessage)
			}
		})
	}
}

func newTestCLIRunner(t *testing.T) (*cliRunner, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	runner := &cliRunner{
		stdout: stdout,
		stderr: stderr,
		loadAWSConfig: func() (*ini.File, error) {
			t.Fatal("unexpected loadAWSConfig() call")
			return nil, nil
		},
		loadEnvConfig: func() (*config.ProfileConfig, error) {
			t.Fatal("unexpected loadEnvConfig() call")
			return nil, nil
		},
		getProfiles: func(*ini.File) []string {
			t.Fatal("unexpected getProfiles() call")
			return nil
		},
		getProfile: func(string, *ini.File) (*config.ProfileConfig, error) {
			t.Fatal("unexpected getProfile() call")
			return nil, nil
		},
		selectProfile: func([]string) (string, error) {
			t.Fatal("unexpected selectProfile() call")
			return "", nil
		},
		getCredentials: func(string, *config.ProfileConfig, *ini.File, bool, time.Duration) (*config.AssumeRoleResult, error) {
			t.Fatal("unexpected getCredentials() call")
			return nil, nil
		},
	}
	return runner, stdout, stderr
}

func testAssumeRoleResult(profileName string) *config.AssumeRoleResult {
	return &config.AssumeRoleResult{
		AccessKeyID:     "access-key",
		SecretAccessKey: "secret-key",
		SessionToken:    "session-token",
		Expiration:      "2030-01-01T00:00:00Z",
		ProfileName:     profileName,
		EndpointURL:     "https://storage.example.com",
	}
}
