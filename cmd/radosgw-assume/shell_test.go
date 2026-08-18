package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestPrepareInteractiveShell(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())

	tests := []struct {
		name              string
		shell             string
		wantKind          shellKind
		wantCommandPrefix []string
		wantEnvironment   string
		wantInitText      string
	}{
		{name: "bash", shell: "/bin/bash", wantKind: shellBash, wantCommandPrefix: []string{"/bin/bash", "--rcfile"}, wantEnvironment: "RADOSGW_ASSUME_INIT_FILE", wantInitText: "PROMPT_COMMAND"},
		{name: "zsh", shell: "/bin/zsh", wantKind: shellZsh, wantCommandPrefix: []string{"/bin/zsh", "-i"}, wantEnvironment: "ZDOTDIR", wantInitText: "POWERLEVEL9K_LEFT_PROMPT_ELEMENTS"},
		{name: "sh", shell: "/bin/sh", wantKind: shellPOSIX, wantCommandPrefix: []string{"/bin/sh", "-i"}, wantEnvironment: "ENV", wantInitText: "PS1="},
		{name: "ksh", shell: "/bin/ksh", wantKind: shellKsh, wantCommandPrefix: []string{"/bin/ksh", "-i"}, wantEnvironment: "ENV", wantInitText: "PS1="},
		{name: "fish", shell: "/usr/bin/fish", wantKind: shellFish, wantCommandPrefix: []string{"/usr/bin/fish", "-i"}, wantEnvironment: "SHELL_PROMPT_PREFIX"},
		{name: "unknown", shell: "/bin/tcsh", wantKind: shellUnknown, wantCommandPrefix: []string{"/bin/tcsh", "-i"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			environment := []string{
				"HOME=/test/home",
				"SHELL=" + tt.shell,
				"RADOSGW_ASSUME_PROMPT_LABEL=rgw:test",
				"ZDOTDIR=/test/zdotdir",
				"ENV=/test/shrc",
			}
			launch, err := prepareInteractiveShell(environment, true)
			if err != nil {
				t.Fatalf("prepareInteractiveShell() error = %v", err)
			}
			defer launch.cleanup()

			if !reflect.DeepEqual(launch.command[:len(tt.wantCommandPrefix)], tt.wantCommandPrefix) {
				t.Errorf("command = %v, want prefix %v", launch.command, tt.wantCommandPrefix)
			}
			if launch.promptModified != (tt.wantKind != shellUnknown) {
				t.Errorf("promptModified = %v", launch.promptModified)
			}
			if tt.wantEnvironment == "" {
				return
			}

			value, found := environmentLookup(launch.environment, tt.wantEnvironment)
			if !found || value == "" {
				t.Fatalf("environment missing %s: %v", tt.wantEnvironment, launch.environment)
			}
			if tt.wantInitText == "" {
				return
			}
			initFile := value
			if tt.wantEnvironment == "ZDOTDIR" {
				initFile = filepath.Join(value, ".zshrc")
			}
			contents, err := os.ReadFile(initFile)
			if err != nil {
				t.Fatalf("read init file: %v", err)
			}
			if !strings.Contains(string(contents), tt.wantInitText) {
				t.Errorf("init file missing %q", tt.wantInitText)
			}
		})
	}
}

func TestPrepareInteractiveShellWithoutPrompt(t *testing.T) {
	temporaryDirectory := t.TempDir()
	t.Setenv("TMPDIR", temporaryDirectory)
	environment := []string{"PATH=/bin", "SHELL=/bin/zsh"}

	launch, err := prepareInteractiveShell(environment, false)
	if err != nil {
		t.Fatalf("prepareInteractiveShell() error = %v", err)
	}
	defer launch.cleanup()

	if !reflect.DeepEqual(launch.command, []string{"/bin/zsh", "-i"}) {
		t.Errorf("command = %v", launch.command)
	}
	if !reflect.DeepEqual(launch.environment, environment) {
		t.Errorf("environment = %v, want unchanged", launch.environment)
	}
	if launch.promptModified {
		t.Error("promptModified = true")
	}
	entries, err := os.ReadDir(temporaryDirectory)
	if err != nil {
		t.Fatalf("read temporary directory: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("temporary directory contains %d entries, want none", len(entries))
	}
}
