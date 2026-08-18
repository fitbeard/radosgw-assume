package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/fitbeard/radosgw-assume/internal/config"
	"github.com/fitbeard/radosgw-assume/internal/credentialcache"
	"github.com/fitbeard/radosgw-assume/internal/ui"

	"gopkg.in/ini.v1"
)

func TestCLIRunnerCacheActions(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		configure  func(*cliRunner)
		wantOutput []string
	}{
		{
			name: "status",
			args: []string{"cache", "status"},
			configure: func(runner *cliRunner) {
				runner.inspectCache = func() (credentialcache.Summary, error) {
					return credentialcache.Summary{
						Directory: "/cache/credentials-v1",
						Valid:     2,
						Expired:   1,
						Invalid:   1,
					}, nil
				}
			},
			wantOutput: []string{
				"Credential cache: /cache/credentials-v1",
				"Entries: 4",
				"Valid: 2",
				"Expired: 1",
				"Invalid: 1",
			},
		},
		{
			name: "empty status",
			args: []string{"cache", "status"},
			configure: func(runner *cliRunner) {
				runner.inspectCache = func() (credentialcache.Summary, error) {
					return credentialcache.Summary{Directory: "/cache/credentials-v1"}, nil
				}
			},
			wantOutput: []string{"Credential cache: /cache/credentials-v1", "Entries: 0"},
		},
		{
			name: "clear",
			args: []string{"cache", "clear"},
			configure: func(runner *cliRunner) {
				runner.clearCache = func() (credentialcache.ClearResult, error) {
					return credentialcache.ClearResult{Directory: "/cache/credentials-v1", Removed: 3}, nil
				}
			},
			wantOutput: []string{"Cleared 3 credential cache entries from /cache/credentials-v1"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner, stdout, stderr := newTestCLIRunner(t)
			test.configure(runner)
			if exitCode := runner.run("radosgw-assume", test.args); exitCode != 0 {
				t.Fatalf("run() exit code = %d, want 0; stderr: %s", exitCode, stderr.String())
			}
			for _, want := range test.wantOutput {
				if !strings.Contains(stdout.String(), want) {
					t.Errorf("run() output = %q, want it to contain %q", stdout.String(), want)
				}
			}
			if stderr.Len() != 0 {
				t.Errorf("run() stderr = %q, want empty", stderr.String())
			}
		})
	}
}

func TestCLIRunnerCacheErrors(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		configure func(*cliRunner)
		want      string
	}{
		{
			name: "inspect",
			args: []string{"cache", "status"},
			configure: func(runner *cliRunner) {
				runner.inspectCache = func() (credentialcache.Summary, error) {
					return credentialcache.Summary{}, errors.New("inspect failure")
				}
			},
			want: "Error inspecting credential cache: inspect failure",
		},
		{
			name: "clear",
			args: []string{"cache", "clear"},
			configure: func(runner *cliRunner) {
				runner.clearCache = func() (credentialcache.ClearResult, error) {
					return credentialcache.ClearResult{}, errors.New("clear failure")
				}
			},
			want: "Error clearing credential cache: clear failure",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner, stdout, stderr := newTestCLIRunner(t)
			test.configure(runner)
			if exitCode := runner.run("radosgw-assume", test.args); exitCode != 1 {
				t.Errorf("run() exit code = %d, want 1", exitCode)
			}
			if stdout.Len() != 0 {
				t.Errorf("run() stdout = %q, want empty", stdout.String())
			}
			if !strings.Contains(stderr.String(), test.want) {
				t.Errorf("run() stderr = %q, want it to contain %q", stderr.String(), test.want)
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

func TestCLIRunnerDefersInteractiveExportFromBackgroundPipe(t *testing.T) {
	runner, stdout, stderr := newTestCLIRunner(t)
	runner.deferInteractiveExport = true

	exitCode := runner.run("/path/radosgw assume", []string{"--verbose", "--duration", "2h"})
	if exitCode != 0 {
		t.Fatalf("run() exit code = %d, want 0; stderr: %s", exitCode, stderr.String())
	}
	want := "eval \"$(RADOSGW_ASSUME_FOREGROUND_EXPORT=1 '/path/radosgw assume' '--verbose' '--duration' '2h')\"\n"
	if stdout.String() != want {
		t.Errorf("run() stdout = %q, want %q", stdout.String(), want)
	}
	if stderr.Len() != 0 {
		t.Errorf("run() stderr = %q, want empty", stderr.String())
	}
}

func TestShouldDeferInteractiveExport(t *testing.T) {
	t.Setenv(foregroundExportEnvironment, "")
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error = %v", err)
	}
	t.Cleanup(func() {
		_ = reader.Close()
		_ = writer.Close()
	})

	if !shouldDeferInteractiveExport(writer, false) {
		t.Error("background named-pipe output should defer interactive export")
	}
	if shouldDeferInteractiveExport(writer, true) {
		t.Error("foreground named-pipe output should not defer interactive export")
	}

	t.Setenv(foregroundExportEnvironment, "1")
	if shouldDeferInteractiveExport(writer, false) {
		t.Error("foreground-export child should not defer recursively")
	}
}

func TestForegroundExportCanBeSourcedFromZshProcessSubstitution(t *testing.T) {
	exporter := filepath.Join(t.TempDir(), "radosgw-assume-test-exporter")
	exporterScript := "#!/bin/sh\n" +
		"test \"$RADOSGW_ASSUME_FOREGROUND_EXPORT\" = 1 || exit 9\n" +
		"printf \"export RADOSGW_SOURCE_TEST='works'\\n\"\n"
	if err := os.WriteFile(exporter, []byte(exporterScript), 0o700); err != nil {
		t.Fatalf("write exporter: %v", err)
	}

	var wrapper bytes.Buffer
	fprintForegroundExport(&wrapper, exporter, nil)

	shellPath, err := exec.LookPath("zsh")
	if err != nil {
		t.Skip("zsh is unavailable")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, shellPath, "-c", `source <(printf '%s\n' "$RADOSGW_TEST_WRAPPER"); printf '%s\n' "$RADOSGW_SOURCE_TEST"`)
	command.Env = append(os.Environ(), "RADOSGW_TEST_WRAPPER="+wrapper.String())
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("source process substitution did not exit: %v", ctx.Err())
	}
	if err != nil {
		t.Fatalf("source process substitution failed: %v; output: %s", err, output)
	}
	if string(output) != "works\n" {
		t.Errorf("source process substitution output = %q, want works", output)
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
	runner.getCredentials = func(_ context.Context, profileName string, gotProfile *config.ProfileConfig, gotConfig *ini.File, verbose bool, sessionDuration time.Duration) (*config.AssumeRoleResult, error) {
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
	runner.getCredentials = func(_ context.Context, profileName string, gotProfile *config.ProfileConfig, awsConfig *ini.File, verbose bool, sessionDuration time.Duration) (*config.AssumeRoleResult, error) {
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

func TestCLIRunnerCancellation(t *testing.T) {
	runner, stdout, stderr := newTestCLIRunner(t)
	awsConfig := ini.Empty()
	profileConfig := &config.ProfileConfig{}
	runner.loadAWSConfig = func() (*ini.File, error) { return awsConfig, nil }
	runner.getProfile = func(string, *ini.File) (*config.ProfileConfig, error) { return profileConfig, nil }

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	runner.getCredentials = func(gotContext context.Context, _ string, _ *config.ProfileConfig, _ *ini.File, _ bool, _ time.Duration) (*config.AssumeRoleResult, error) {
		if gotContext != ctx {
			t.Error("getCredentials() did not receive the caller context")
		}
		return nil, gotContext.Err()
	}

	if exitCode := runner.runContext(ctx, "radosgw-assume", []string{"--profile", "profile"}); exitCode != 130 {
		t.Errorf("runContext() exit code = %d, want 130", exitCode)
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Errorf("cancellation output = (stdout %q, stderr %q), want no output", stdout.String(), stderr.String())
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
	runner.getCredentials = func(_ context.Context, profileName string, gotProfile *config.ProfileConfig, gotConfig *ini.File, verbose bool, sessionDuration time.Duration) (*config.AssumeRoleResult, error) {
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

func TestCLIRunnerCredentialProcess(t *testing.T) {
	runner, stdout, stderr := newTestCLIRunner(t)
	awsConfig := ini.Empty()
	profileConfig := &config.ProfileConfig{RoleSessionName: "config-session"}
	wantResult := testAssumeRoleResult("profile")
	wantNoCache := false
	var authenticationOutput bytes.Buffer
	runner.openTerminal = func() (io.WriteCloser, error) {
		return testWriteCloser{Writer: &authenticationOutput}, nil
	}

	runner.loadAWSConfig = func() (*ini.File, error) { return awsConfig, nil }
	runner.getProfile = func(profileName string, gotConfig *ini.File) (*config.ProfileConfig, error) {
		if profileName != "profile" || gotConfig != awsConfig {
			t.Errorf("getProfile() = (%q, %p), want profile and test config", profileName, gotConfig)
		}
		return profileConfig, nil
	}
	runner.getProcessCredentials = func(_ context.Context, profileName string, gotProfile *config.ProfileConfig, gotConfig *ini.File, verbose bool, sessionDuration time.Duration, output io.Writer, noCache bool) (*config.AssumeRoleResult, error) {
		if profileName != "profile" || gotProfile != profileConfig || gotConfig != awsConfig {
			t.Error("getProcessCredentials() received unexpected configuration")
		}
		if !verbose || sessionDuration != 2*time.Hour {
			t.Errorf("getCredentials() options = (verbose %v, duration %v), want true and 2h", verbose, sessionDuration)
		}
		if gotProfile.RoleSessionName != "process-session" {
			t.Errorf("session name = %q, want process-session", gotProfile.RoleSessionName)
		}
		if noCache != wantNoCache {
			t.Errorf("getProcessCredentials() noCache = %v, want %v", noCache, wantNoCache)
		}
		_, _ = fmt.Fprint(output, "authentication interaction")
		return wantResult, nil
	}

	exitCode := runner.run("radosgw-assume", []string{
		"credential-process", "--profile", "profile", "--verbose", "--duration", "2h", "--session", "process-session",
	})
	if exitCode != 0 {
		t.Fatalf("run() exit code = %d, want 0; stderr: %s", exitCode, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("run() stderr = %q, want empty", stderr.String())
	}
	if authenticationOutput.String() != "authentication interaction" {
		t.Errorf("authentication output = %q, want terminal interaction", authenticationOutput.String())
	}

	var output map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("credential-process stdout is not valid JSON: %v; output: %s", err, stdout.String())
	}
	want := map[string]any{
		"Version":         float64(1),
		"AccessKeyId":     wantResult.AccessKeyID,
		"SecretAccessKey": wantResult.SecretAccessKey,
		"SessionToken":    wantResult.SessionToken,
		"Expiration":      wantResult.Expiration,
	}
	if !reflect.DeepEqual(output, want) {
		t.Errorf("credential-process output = %#v, want %#v", output, want)
	}

	runner.stdout = cliErrorWriter{}
	stderr.Reset()
	wantNoCache = true
	exitCode = runner.run("radosgw-assume", []string{"credential-process", "--profile", "profile", "--verbose", "--duration", "2h", "--session", "process-session", "--no-cache"})
	if exitCode != 1 {
		t.Errorf("run() with output failure exit code = %d, want 1", exitCode)
	}
	if !strings.Contains(stderr.String(), "Error: write credential process output: write failed") {
		t.Errorf("run() stderr = %q, want output failure", stderr.String())
	}
}

func TestCLIRunnerCredentialProcessFallsBackToStderr(t *testing.T) {
	runner, stdout, stderr := newTestCLIRunner(t)
	runner.loadAWSConfig = func() (*ini.File, error) { return ini.Empty(), nil }
	runner.getProfile = func(string, *ini.File) (*config.ProfileConfig, error) {
		return &config.ProfileConfig{}, nil
	}
	runner.openTerminal = func() (io.WriteCloser, error) {
		return nil, errors.New("no controlling terminal")
	}
	runner.getProcessCredentials = func(_ context.Context, _ string, _ *config.ProfileConfig, _ *ini.File, _ bool, _ time.Duration, output io.Writer, _ bool) (*config.AssumeRoleResult, error) {
		_, _ = fmt.Fprint(output, "authentication interaction")
		return testAssumeRoleResult("profile"), nil
	}

	exitCode := runner.run("radosgw-assume", []string{"credential-process", "--profile", "profile"})
	if exitCode != 0 {
		t.Fatalf("run() exit code = %d, want 0; stderr: %s", exitCode, stderr.String())
	}
	if stderr.String() != "authentication interaction" {
		t.Errorf("run() stderr = %q, want fallback interaction", stderr.String())
	}
	if !json.Valid(stdout.Bytes()) {
		t.Errorf("run() stdout = %q, want valid credential JSON", stdout.String())
	}
}

type cliErrorWriter struct{}

func (cliErrorWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

type testWriteCloser struct {
	io.Writer
}

func (testWriteCloser) Close() error {
	return nil
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
	runner.getCredentials = func(_ context.Context, profileName string, gotProfile *config.ProfileConfig, gotConfig *ini.File, verbose bool, sessionDuration time.Duration) (*config.AssumeRoleResult, error) {
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
	runner.getCredentials = func(_ context.Context, profileName string, _ *config.ProfileConfig, _ *ini.File, _ bool, _ time.Duration) (*config.AssumeRoleResult, error) {
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
			name: "no profiles",
			configure: func(r *cliRunner) {
				r.loadAWSConfig = func() (*ini.File, error) { return ini.Empty(), nil }
				r.getProfiles = func(*ini.File) []string { return nil }
			},
			wantMessage: "No RadosGW profiles found in AWS config file",
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
				r.getCredentials = func(context.Context, string, *config.ProfileConfig, *ini.File, bool, time.Duration) (*config.AssumeRoleResult, error) {
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
				r.getCredentials = func(context.Context, string, *config.ProfileConfig, *ini.File, bool, time.Duration) (*config.AssumeRoleResult, error) {
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
				r.getCredentials = func(context.Context, string, *config.ProfileConfig, *ini.File, bool, time.Duration) (*config.AssumeRoleResult, error) {
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
		getCredentials: func(context.Context, string, *config.ProfileConfig, *ini.File, bool, time.Duration) (*config.AssumeRoleResult, error) {
			t.Fatal("unexpected getCredentials() call")
			return nil, nil
		},
		getProcessCredentials: func(context.Context, string, *config.ProfileConfig, *ini.File, bool, time.Duration, io.Writer, bool) (*config.AssumeRoleResult, error) {
			t.Fatal("unexpected getProcessCredentials() call")
			return nil, nil
		},
		inspectCache: func() (credentialcache.Summary, error) {
			t.Fatal("unexpected inspectCache() call")
			return credentialcache.Summary{}, nil
		},
		clearCache: func() (credentialcache.ClearResult, error) {
			t.Fatal("unexpected clearCache() call")
			return credentialcache.ClearResult{}, nil
		},
		openTerminal: func() (io.WriteCloser, error) {
			t.Fatal("unexpected openTerminal() call")
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
