package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

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

func TestZshPromptBootstrapRestoresTemporaryHistoryPath(t *testing.T) {
	shell, err := exec.LookPath("zsh")
	if err != nil {
		t.Skip("zsh is not installed")
	}
	temporaryDirectory := t.TempDir()
	homeDirectory := filepath.Join(temporaryDirectory, "home")
	if err := os.Mkdir(homeDirectory, 0o700); err != nil {
		t.Fatalf("create home directory: %v", err)
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

	initDirectory := environmentValue(launch.environment, "ZDOTDIR")
	launch.environment = environmentWithOverrides(launch.environment, []string{
		"HISTFILE=" + filepath.Join(initDirectory, ".zsh_history"),
	})
	command := exec.Command(launch.command[0], append(launch.command[1:], "-c", `print -r -- "$HISTFILE"`)...)
	command.Env = launch.environment
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("zsh bootstrap error = %v; output: %s", err, output)
	}

	wantHistoryFile := filepath.Join(homeDirectory, ".zsh_history")
	if got := strings.TrimSpace(string(output)); got != wantHistoryFile {
		t.Errorf("HISTFILE = %q, want %q", got, wantHistoryFile)
	}
}
