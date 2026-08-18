package main

import (
	"reflect"
	"strings"
	"testing"
	"time"
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
		{
			name: "credential process with profile",
			args: []string{"credential-process", "--profile", "profile", "--duration", "2h", "--verbose"},
			want: cliOptions{
				action:          actionCredentialProcess,
				profileName:     "profile",
				verbose:         true,
				sessionDuration: 2 * time.Hour,
			},
		},
		{
			name: "credential process with environment configuration",
			args: []string{"credential-process", "--env"},
			want: cliOptions{action: actionCredentialProcess, useEnv: true, sessionDuration: time.Hour},
		},
		{
			name: "credential process without cache",
			args: []string{"credential-process", "--profile", "profile", "--no-cache"},
			want: cliOptions{action: actionCredentialProcess, profileName: "profile", noCache: true, sessionDuration: time.Hour},
		},
		{
			name: "credential process help",
			args: []string{"credential-process", "--help"},
			want: cliOptions{action: actionHelp, sessionDuration: time.Hour},
		},
		{
			name: "cache status",
			args: []string{"cache", "status"},
			want: cliOptions{action: actionCacheStatus, sessionDuration: time.Hour},
		},
		{
			name: "cache clear",
			args: []string{"cache", "clear"},
			want: cliOptions{action: actionCacheClear, sessionDuration: time.Hour},
		},
		{
			name: "cache help",
			args: []string{"cache", "--help"},
			want: cliOptions{action: actionHelp, sessionDuration: time.Hour},
		},
		{
			name: "cache subcommand help",
			args: []string{"cache", "status", "--help"},
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
		{name: "credential process missing configuration", args: []string{"credential-process"}, wantMessage: "credential-process requires -p/--profile or --env"},
		{name: "credential process positional profile", args: []string{"credential-process", "profile"}, wantMessage: "unexpected credential-process argument 'profile'"},
		{name: "credential process delimiter", args: []string{"credential-process", "--"}, wantMessage: "unexpected argument '--'"},
		{name: "credential process prompt option", args: []string{"credential-process", "-p", "profile", "--no-prompt"}, wantMessage: "--no-prompt can only be used with the shell command"},
		{name: "cache option without credential process", args: []string{"--profile", "profile", "--no-cache"}, wantMessage: "--no-cache can only be used with the credential-process command"},
		{name: "cache command missing", args: []string{"cache"}, wantMessage: "cache requires 'status' or 'clear'"},
		{name: "cache command unknown", args: []string{"cache", "prune"}, wantMessage: "unknown cache command 'prune'"},
		{name: "cache status argument", args: []string{"cache", "status", "extra"}, wantMessage: "unexpected cache argument 'extra'"},
		{name: "cache clear flag", args: []string{"cache", "clear", "--verbose"}, wantMessage: "unexpected cache argument '--verbose'"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCLIArguments("custom-name", tt.args)
			if err == nil {
				t.Fatal("parseCLIArguments() expected an error")
			}
			if !reflect.DeepEqual(got, cliOptions{}) {
				t.Errorf("parseCLIArguments() options = %+v on error, want zero value", got)
			}
			if !strings.Contains(err.Error(), tt.wantMessage) {
				t.Errorf("parseCLIArguments() error = %q, want it to contain %q", err, tt.wantMessage)
			}
		})
	}
}
