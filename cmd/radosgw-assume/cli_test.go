package main

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/fitbeard/radosgw-assume/internal/config"
	"github.com/fitbeard/radosgw-assume/internal/ui"

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
			args: []string{"--profile", "profile", "--verbose", "--duration", "2h", "--session", "test-session"},
			want: cliOptions{
				profileName:     "profile",
				verbose:         true,
				sessionDuration: 2 * time.Hour,
				sessionName:     "test-session",
			},
		},
		{
			name: "short options",
			args: []string{"-p", "profile", "-v", "-d", "3600", "-s", "test-session"},
			want: cliOptions{
				profileName:     "profile",
				verbose:         true,
				sessionDuration: time.Hour,
				sessionName:     "test-session",
			},
		},
		{
			name: "environment options",
			args: []string{"-v", "-e"},
			want: cliOptions{verbose: true, useEnv: true, sessionDuration: time.Hour},
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
		{
			name: "profile named version",
			args: []string{"--profile", "version"},
			want: cliOptions{profileName: "version", sessionDuration: time.Hour},
		},
		{
			name: "exec with profile",
			args: []string{"exec", "--profile", "profile", "--", "aws", "s3", "ls", "--recursive"},
			want: cliOptions{
				action:          actionExec,
				profileName:     "profile",
				sessionDuration: time.Hour,
				command:         []string{"aws", "s3", "ls", "--recursive"},
			},
		},
		{
			name: "exec with interactive profile",
			args: []string{"exec", "--", "version"},
			want: cliOptions{action: actionExec, sessionDuration: time.Hour, command: []string{"version"}},
		},
		{
			name: "exec with environment configuration",
			args: []string{"exec", "--env", "--verbose", "--", "command", "--command-flag"},
			want: cliOptions{
				action:          actionExec,
				verbose:         true,
				useEnv:          true,
				sessionDuration: time.Hour,
				command:         []string{"command", "--command-flag"},
			},
		},
		{
			name: "exec help",
			args: []string{"exec", "--help"},
			want: cliOptions{action: actionHelp, sessionDuration: time.Hour},
		},
		{
			name: "shell with profile",
			args: []string{"shell", "--profile", "profile", "--duration", "2h"},
			want: cliOptions{
				action:          actionShell,
				profileName:     "profile",
				sessionDuration: 2 * time.Hour,
			},
		},
		{
			name: "shell with interactive profile",
			args: []string{"shell"},
			want: cliOptions{action: actionShell, sessionDuration: time.Hour},
		},
		{
			name: "shell with environment configuration",
			args: []string{"shell", "--env", "--verbose", "--no-prompt"},
			want: cliOptions{
				action:          actionShell,
				verbose:         true,
				useEnv:          true,
				noPrompt:        true,
				sessionDuration: time.Hour,
			},
		},
		{
			name: "shell help",
			args: []string{"shell", "--help"},
			want: cliOptions{action: actionHelp, sessionDuration: time.Hour},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCLIArguments("radosgw-assume", tt.args)
			if err != nil {
				t.Fatalf("parseCLIArguments() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
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
		{name: "duration value missing", args: []string{"--duration"}, wantMessage: "duration flag requires a value\nUsage: custom-name -d 1h [-p PROFILE]"},
		{name: "duration malformed", args: []string{"--duration", "tomorrow"}, wantMessage: "invalid duration 'tomorrow'"},
		{name: "duration too short", args: []string{"--duration", "1m"}, wantMessage: "duration cannot be less than 15 minutes"},
		{name: "session value missing", args: []string{"--session"}, wantMessage: "session name flag requires a value\nUsage: custom-name -s my-session [-p PROFILE]"},
		{name: "session invalid", args: []string{"--session", "not_valid"}, wantMessage: "invalid session name 'not_valid'"},
		{name: "profile value missing", args: []string{"--profile"}, wantMessage: "profile flag requires a value"},
		{name: "profile value is another flag", args: []string{"--profile", "--verbose"}, wantMessage: "profile flag requires a value"},
		{name: "profile empty", args: []string{"--profile", ""}, wantMessage: "profile name cannot be empty"},
		{name: "profile repeated", args: []string{"--profile", "first", "-p", "second"}, wantMessage: "profile flag specified more than once"},
		{name: "profile and environment", args: []string{"--profile", "profile", "--env"}, wantMessage: "--env and --profile cannot be used together"},
		{name: "unknown flag", args: []string{"--unknown"}, wantMessage: "unknown flag '--unknown'"},
		{name: "positional profile", args: []string{"profile"}, wantMessage: "unexpected argument 'profile': select a profile with -p or --profile"},
		{name: "version with options", args: []string{"version", "--verbose"}, wantMessage: "unexpected argument 'version'"},
		{name: "exec missing delimiter and command", args: []string{"exec", "--profile", "profile"}, wantMessage: "exec requires a command after '--'"},
		{name: "exec missing command", args: []string{"exec", "--profile", "profile", "--"}, wantMessage: "exec requires a command after '--'"},
		{name: "exec command without delimiter", args: []string{"exec", "--profile", "profile", "aws", "s3", "ls"}, wantMessage: "unexpected exec argument 'aws': command must follow '--'"},
		{name: "delimiter without exec", args: []string{"--profile", "profile", "--", "aws"}, wantMessage: "unexpected argument '--'"},
		{name: "exec profile and environment", args: []string{"exec", "--profile", "profile", "--env", "--", "aws"}, wantMessage: "--env and --profile cannot be used together"},
		{name: "shell positional argument", args: []string{"shell", "command"}, wantMessage: "unexpected shell argument 'command'"},
		{name: "shell delimiter", args: []string{"shell", "--"}, wantMessage: "unexpected argument '--'"},
		{name: "shell profile and environment", args: []string{"shell", "--profile", "profile", "--env"}, wantMessage: "--env and --profile cannot be used together"},
		{name: "prompt option without shell", args: []string{"--no-prompt"}, wantMessage: "--no-prompt can only be used with the shell command"},
		{name: "prompt option with exec", args: []string{"exec", "--no-prompt", "--", "aws"}, wantMessage: "--no-prompt can only be used with the shell command"},
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
		if profileName != "version" {
			t.Errorf("getProfile() name = %q, want version", profileName)
		}
		if gotConfig != awsConfig {
			t.Error("getProfile() received a different AWS config")
		}
		return profileConfig, nil
	}
	runner.getCredentials = func(profileName string, gotProfile *config.ProfileConfig, gotConfig *ini.File, verbose bool, sessionDuration time.Duration) (*config.AssumeRoleResult, error) {
		if profileName != "version" {
			t.Errorf("getCredentials() profile = %q, want version", profileName)
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
		return testAssumeRoleResult("version"), nil
	}

	exitCode := runner.run("radosgw-assume", []string{"--verbose", "--duration", "2h", "--session", "cli-session", "--profile", "version"})
	if exitCode != 0 {
		t.Fatalf("run() exit code = %d, want 0; stderr: %s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "export AWS_PROFILE='version'") {
		t.Errorf("run() stdout = %q, want profile export", stdout.String())
	}
	if !strings.Contains(stderr.String(), "# Credentials exported for profile: version") {
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

func TestCLIRunnerExecCommand(t *testing.T) {
	runner, stdout, stderr := newTestCLIRunner(t)
	awsConfig := ini.Empty()
	profileConfig := &config.ProfileConfig{}
	wantResult := testAssumeRoleResult("profile")
	baseEnvironment := []string{
		"PATH=/test/bin",
		"UNRELATED=value",
		"AWS_ACCESS_KEY_ID=stale-access-key",
		"AWS_PROFILE=stale-profile",
		"AWS_ENDPOINT_URL=https://stale.example.com",
		"RADOSGW_OIDC_TOKEN=source-token",
	}

	runner.loadAWSConfig = func() (*ini.File, error) { return awsConfig, nil }
	runner.getProfile = func(profileName string, gotConfig *ini.File) (*config.ProfileConfig, error) {
		if profileName != "profile" || gotConfig != awsConfig {
			t.Errorf("getProfile() = (%q, %p), want profile and test config", profileName, gotConfig)
		}
		return profileConfig, nil
	}
	runner.getCredentials = func(profileName string, gotProfile *config.ProfileConfig, gotConfig *ini.File, verbose bool, sessionDuration time.Duration) (*config.AssumeRoleResult, error) {
		if profileName != "profile" || gotProfile != profileConfig || gotConfig != awsConfig {
			t.Error("getCredentials() received unexpected configuration")
		}
		if verbose || sessionDuration != time.Hour {
			t.Errorf("getCredentials() options = (verbose %v, duration %v)", verbose, sessionDuration)
		}
		return wantResult, nil
	}
	runner.environ = func() []string { return baseEnvironment }
	runner.execCommand = func(command, environment []string) error {
		if !reflect.DeepEqual(command, []string{"aws", "s3", "ls", "--recursive"}) {
			t.Errorf("execCommand() command = %v", command)
		}
		assertCommandEnvironment(t, environment, map[string]string{
			"PATH":                      "/test/bin",
			"UNRELATED":                 "value",
			"AWS_ACCESS_KEY_ID":         wantResult.AccessKeyID,
			"AWS_SECRET_ACCESS_KEY":     wantResult.SecretAccessKey,
			"AWS_SESSION_TOKEN":         wantResult.SessionToken,
			"AWS_PROFILE":               wantResult.ProfileName,
			"AWS_ENDPOINT_URL":          wantResult.EndpointURL,
			"AWS_CREDENTIAL_EXPIRATION": wantResult.Expiration,
			"AWS_SESSION_EXPIRATION":    wantResult.Expiration,
		})
		assertEnvironmentMissing(t, environment, "RADOSGW_OIDC_TOKEN")
		return nil
	}

	exitCode := runner.run("radosgw-assume", []string{"exec", "--profile", "profile", "--", "aws", "s3", "ls", "--recursive"})
	if exitCode != 0 {
		t.Fatalf("run() exit code = %d, want 0; stderr: %s", exitCode, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("run() stdout = %q, must not print credential exports", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("run() stderr = %q, want empty", stderr.String())
	}
}

func TestCLIRunnerShell(t *testing.T) {
	runner, stdout, stderr := newTestCLIRunner(t)
	awsConfig := ini.Empty()
	profileConfig := &config.ProfileConfig{}
	wantResult := testAssumeRoleResult("profile")
	baseEnvironment := []string{
		"PATH=/test/bin",
		"SHELL=/test/bin/zsh",
		"AWS_PROFILE=stale-profile",
		"RADOSGW_ASSUME_SHELL=stale",
		"RADOSGW_ASSUME_PROFILE=stale-profile",
		"RADOSGW_OIDC_TOKEN=source-token",
	}

	runner.loadAWSConfig = func() (*ini.File, error) { return awsConfig, nil }
	runner.getProfile = func(profileName string, gotConfig *ini.File) (*config.ProfileConfig, error) {
		if profileName != "profile" || gotConfig != awsConfig {
			t.Errorf("getProfile() = (%q, %p), want profile and test config", profileName, gotConfig)
		}
		return profileConfig, nil
	}
	runner.getCredentials = func(profileName string, gotProfile *config.ProfileConfig, gotConfig *ini.File, verbose bool, sessionDuration time.Duration) (*config.AssumeRoleResult, error) {
		if profileName != "profile" || gotProfile != profileConfig || gotConfig != awsConfig {
			t.Error("getCredentials() received unexpected configuration")
		}
		if verbose || sessionDuration != time.Hour {
			t.Errorf("getCredentials() options = (verbose %v, duration %v)", verbose, sessionDuration)
		}
		return wantResult, nil
	}
	runner.environ = func() []string { return baseEnvironment }
	runner.execCommand = func(command, environment []string) error {
		if !reflect.DeepEqual(command, []string{"/test/bin/zsh", "-i"}) {
			t.Errorf("execCommand() command = %v", command)
		}
		assertCommandEnvironment(t, environment, map[string]string{
			"PATH":                        "/test/bin",
			"SHELL":                       "/test/bin/zsh",
			"AWS_ACCESS_KEY_ID":           wantResult.AccessKeyID,
			"AWS_SECRET_ACCESS_KEY":       wantResult.SecretAccessKey,
			"AWS_SESSION_TOKEN":           wantResult.SessionToken,
			"AWS_PROFILE":                 wantResult.ProfileName,
			"AWS_ENDPOINT_URL":            wantResult.EndpointURL,
			"AWS_CREDENTIAL_EXPIRATION":   wantResult.Expiration,
			"AWS_SESSION_EXPIRATION":      wantResult.Expiration,
			"RADOSGW_ASSUME_SHELL":        "1",
			"RADOSGW_ASSUME_PROFILE":      wantResult.ProfileName,
			"RADOSGW_ASSUME_PROMPT_LABEL": "rgw:profile",
		})
		assertEnvironmentMissing(t, environment, "RADOSGW_OIDC_TOKEN")
		return nil
	}

	exitCode := runner.run("radosgw-assume", []string{"shell", "--profile", "profile"})
	if exitCode != 0 {
		t.Fatalf("run() exit code = %d, want 0; stderr: %s", exitCode, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("run() stdout = %q, must not print credential exports", stdout.String())
	}
	for _, want := range []string{
		"# Entering RadosGW shell for profile: profile",
		"# Credentials valid until: " + wantResult.Expiration,
		"# Prompt marker: [rgw:profile]",
		"# Type 'exit' or press Ctrl+D to return.",
	} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("run() stderr = %q, want it to contain %q", stderr.String(), want)
		}
	}
}

func TestCredentialEnvironmentKeepsRealEnvironmentProfile(t *testing.T) {
	result := testAssumeRoleResult("env")
	environment := credentialEnvironment([]string{
		"AWS_PROFILE=existing-profile",
		"AWS_ACCESS_KEY_ID=stale-access-key",
		"RADOSGW_OIDC_TOKEN=source-token",
	}, result)

	assertCommandEnvironment(t, environment, map[string]string{
		"AWS_PROFILE":               "existing-profile",
		"AWS_ACCESS_KEY_ID":         result.AccessKeyID,
		"AWS_SECRET_ACCESS_KEY":     result.SecretAccessKey,
		"AWS_SESSION_TOKEN":         result.SessionToken,
		"AWS_ENDPOINT_URL":          result.EndpointURL,
		"AWS_CREDENTIAL_EXPIRATION": result.Expiration,
		"AWS_SESSION_EXPIRATION":    result.Expiration,
	})
	assertEnvironmentMissing(t, environment, "RADOSGW_OIDC_TOKEN")
}

func assertCommandEnvironment(t *testing.T, environment []string, want map[string]string) {
	t.Helper()

	values := make(map[string]string, len(environment))
	counts := make(map[string]int, len(environment))
	for _, variable := range environment {
		name, value, found := strings.Cut(variable, "=")
		if !found {
			t.Errorf("environment entry %q has no '='", variable)
			continue
		}
		values[name] = value
		counts[name]++
	}
	for name, wantValue := range want {
		if values[name] != wantValue {
			t.Errorf("environment %s = %q, want %q", name, values[name], wantValue)
		}
		if counts[name] != 1 {
			t.Errorf("environment contains %d entries for %s, want 1", counts[name], name)
		}
	}
}

func assertEnvironmentMissing(t *testing.T, environment []string, name string) {
	t.Helper()

	for _, variable := range environment {
		variableName, _, _ := strings.Cut(variable, "=")
		if variableName == name {
			t.Errorf("environment unexpectedly contains %s", name)
		}
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

func TestCLIRunnerInteractiveCancellation(t *testing.T) {
	runner, stdout, stderr := newTestCLIRunner(t)
	runner.loadAWSConfig = func() (*ini.File, error) { return ini.Empty(), nil }
	runner.getProfiles = func(*ini.File) []string { return []string{"profile"} }
	runner.selectProfile = func([]string) (string, error) { return "", ui.ErrSelectionCancelled }

	if exitCode := runner.run("radosgw-assume", nil); exitCode != 0 {
		t.Errorf("run() exit code = %d, want 0", exitCode)
	}
	if stdout.Len() != 0 {
		t.Errorf("run() stdout = %q, want empty", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("run() stderr = %q, want empty", stderr.String())
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
			wantMessage: "Error: unknown flag '--unknown'",
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
			name: "AWS config",
			configure: func(r *cliRunner) {
				r.loadAWSConfig = func() (*ini.File, error) { return nil, errors.New("config failure") }
			},
			wantMessage: "Error loading AWS config: config failure",
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
			args: []string{"--profile", "missing"},
			configure: func(r *cliRunner) {
				r.loadAWSConfig = func() (*ini.File, error) { return ini.Empty(), nil }
				r.getProfile = func(string, *ini.File) (*config.ProfileConfig, error) { return nil, errors.New("profile failure") }
			},
			wantMessage: "Error: profile failure",
		},
		{
			name: "credential acquisition",
			args: []string{"--profile", "profile"},
			configure: func(r *cliRunner) {
				r.loadAWSConfig = func() (*ini.File, error) { return ini.Empty(), nil }
				r.getProfile = func(string, *ini.File) (*config.ProfileConfig, error) { return &config.ProfileConfig{}, nil }
				r.getCredentials = func(string, *config.ProfileConfig, *ini.File, bool, time.Duration) (*config.AssumeRoleResult, error) {
					return nil, errors.New("credential failure")
				}
			},
			wantMessage: "Error: credential failure",
		},
		{
			name: "command execution",
			args: []string{"exec", "--profile", "profile", "--", "command"},
			configure: func(r *cliRunner) {
				r.loadAWSConfig = func() (*ini.File, error) { return ini.Empty(), nil }
				r.getProfile = func(string, *ini.File) (*config.ProfileConfig, error) { return &config.ProfileConfig{}, nil }
				r.getCredentials = func(string, *config.ProfileConfig, *ini.File, bool, time.Duration) (*config.AssumeRoleResult, error) {
					return testAssumeRoleResult("profile"), nil
				}
				r.environ = func() []string { return nil }
				r.execCommand = func([]string, []string) error { return errors.New("execution failure") }
			},
			wantMessage: "Error: execution failure",
		},
		{
			name: "shell execution",
			args: []string{"shell", "--profile", "profile"},
			configure: func(r *cliRunner) {
				r.loadAWSConfig = func() (*ini.File, error) { return ini.Empty(), nil }
				r.getProfile = func(string, *ini.File) (*config.ProfileConfig, error) { return &config.ProfileConfig{}, nil }
				r.getCredentials = func(string, *config.ProfileConfig, *ini.File, bool, time.Duration) (*config.AssumeRoleResult, error) {
					return testAssumeRoleResult("profile"), nil
				}
				r.environ = func() []string { return []string{"SHELL=/bin/sh"} }
				r.execCommand = func([]string, []string) error { return errors.New("shell failure") }
			},
			wantMessage: "Error: shell failure",
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
		environ: func() []string {
			t.Fatal("unexpected environ() call")
			return nil
		},
		execCommand: func([]string, []string) error {
			t.Fatal("unexpected execCommand() call")
			return nil
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
