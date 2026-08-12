package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDetectShell(t *testing.T) {
	tests := map[string]shellKind{
		"/bin/bash":              shellBash,
		"/opt/homebrew/bin/zsh":  shellZsh,
		"/bin/sh":                shellPOSIX,
		"/usr/bin/dash":          shellPOSIX,
		"/opt/local/bin/ash":     shellPOSIX,
		"/bin/ksh":               shellKsh,
		"/usr/local/bin/ksh93":   shellKsh,
		"/opt/homebrew/bin/mksh": shellKsh,
		"/usr/local/bin/fish":    shellFish,
		"/bin/tcsh":              shellUnknown,
	}

	for shell, want := range tests {
		t.Run(filepath.Base(shell), func(t *testing.T) {
			if got := detectShell(shell); got != want {
				t.Errorf("detectShell(%q) = %v, want %v", shell, got, want)
			}
		})
	}
}

func TestPromptLabel(t *testing.T) {
	tests := map[string]string{
		"profile":                                      "rgw:profile",
		"team/prod@example.com":                        "rgw:team/prod@example.com",
		"spaces and $(unsafe) % prompt":                "rgw:spaces-and---unsafe----prompt",
		"1234567890123456789012345678901234567890tail": "rgw:1234567890123456789012345678901234567890",
	}

	for profile, want := range tests {
		if got := promptLabel(profile); got != want {
			t.Errorf("promptLabel(%q) = %q, want %q", profile, got, want)
		}
	}
}

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

func TestShellPromptBootstrap(t *testing.T) {
	tests := []struct {
		name       string
		shell      string
		rcName     string
		rcContents string
		printCode  string
		want       string
	}{
		{name: "bash", shell: "bash", rcName: ".bashrc", rcContents: "PS1='base> '\n", printCode: `printf '%s\n' "$PS1"`, want: "rgw:test"},
		{name: "zsh", shell: "zsh", rcName: ".zshrc", rcContents: "PROMPT='base> '\n", printCode: `print -r -- "$PROMPT"`, want: "rgw:test"},
		{
			name:   "powerlevel10k",
			shell:  "zsh",
			rcName: ".zshrc",
			rcContents: "typeset -ga POWERLEVEL9K_LEFT_PROMPT_ELEMENTS=(dir vcs)\n" +
				"p10k() { return 0 }\n",
			printCode: `print -r -- "${POWERLEVEL9K_LEFT_PROMPT_ELEMENTS[1]}"`,
			want:      "radosgw_assume",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shell, err := exec.LookPath(tt.shell)
			if err != nil {
				t.Skipf("%s is not installed", tt.shell)
			}
			temporaryDirectory := t.TempDir()
			homeDirectory := filepath.Join(temporaryDirectory, "home")
			if err := os.Mkdir(homeDirectory, 0o700); err != nil {
				t.Fatalf("create home directory: %v", err)
			}
			if err := os.WriteFile(filepath.Join(homeDirectory, tt.rcName), []byte(tt.rcContents), 0o600); err != nil {
				t.Fatalf("write shell config: %v", err)
			}
			t.Setenv("TMPDIR", temporaryDirectory)
			environment := []string{
				"HOME=" + homeDirectory,
				"PATH=" + os.Getenv("PATH"),
				"SHELL=" + shell,
				"RADOSGW_ASSUME_PROMPT_LABEL=rgw:test",
			}
			launch, err := prepareInteractiveShell(environment, true)
			if err != nil {
				t.Fatalf("prepareInteractiveShell() error = %v", err)
			}
			defer launch.cleanup()

			command := exec.Command(launch.command[0], append(launch.command[1:], "-c", tt.printCode)...)
			command.Env = launch.environment
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("shell bootstrap error = %v; output: %s", err, output)
			}
			if !strings.Contains(string(output), tt.want) {
				t.Errorf("shell output = %q, want it to contain %q", output, tt.want)
			}
		})
	}
}
