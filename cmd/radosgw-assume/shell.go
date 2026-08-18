package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type shellLaunch struct {
	command        []string
	environment    []string
	promptModified bool
	cleanup        func()
}

func prepareInteractiveShell(environment []string, modifyPrompt bool) (shellLaunch, error) {
	shell := environmentValue(environment, "SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}

	launch := shellLaunch{
		command:     []string{shell, "-i"},
		environment: environment,
		cleanup:     func() {},
	}
	if !modifyPrompt {
		return launch, nil
	}

	switch detectShell(shell) {
	case shellFish:
		launch.environment = environmentWithOverrides(environment, []string{
			"SHELL_PROMPT_PREFIX=\x1b[38;5;75m[" + environmentValue(environment, "RADOSGW_ASSUME_PROMPT_LABEL") + "]\x1b[0m ",
		})
		launch.promptModified = true
		return launch, nil
	case shellUnknown:
		return launch, nil
	}

	initDirectory, err := os.MkdirTemp("", "radosgw-assume-shell-")
	if err != nil {
		return shellLaunch{}, fmt.Errorf("create temporary startup directory: %w", err)
	}
	launch.cleanup = func() { _ = os.RemoveAll(initDirectory) }

	switch detectShell(shell) {
	case shellBash:
		initFile := filepath.Join(initDirectory, "bashrc")
		if err := writeShellInitFile(initFile, bashPromptInit); err != nil {
			launch.cleanup()
			return shellLaunch{}, err
		}
		launch.command = []string{shell, "--rcfile", initFile, "-i"}
		launch.environment = environmentWithOverrides(environment, []string{
			"RADOSGW_ASSUME_INIT_DIR=" + initDirectory,
			"RADOSGW_ASSUME_INIT_FILE=" + initFile,
		})
	case shellZsh:
		if err := writeShellInitFile(filepath.Join(initDirectory, ".zshenv"), zshEnvironmentInit); err != nil {
			launch.cleanup()
			return shellLaunch{}, err
		}
		if err := writeShellInitFile(filepath.Join(initDirectory, ".zshrc"), zshPromptInit); err != nil {
			launch.cleanup()
			return shellLaunch{}, err
		}
		overrides := []string{
			"ZDOTDIR=" + initDirectory,
			"RADOSGW_ASSUME_INIT_DIR=" + initDirectory,
		}
		removedNames := []string{
			"RADOSGW_ASSUME_EFFECTIVE_ZDOTDIR",
			"RADOSGW_ASSUME_EFFECTIVE_ZDOTDIR_SET",
		}
		if originalZDOTDIR, found := environmentLookup(environment, "ZDOTDIR"); found {
			overrides = append(overrides,
				"RADOSGW_ASSUME_ORIGINAL_ZDOTDIR="+originalZDOTDIR,
				"RADOSGW_ASSUME_ORIGINAL_ZDOTDIR_SET=1",
			)
		} else {
			removedNames = append(removedNames,
				"RADOSGW_ASSUME_ORIGINAL_ZDOTDIR",
				"RADOSGW_ASSUME_ORIGINAL_ZDOTDIR_SET",
			)
		}
		launch.environment = environmentWithOverrides(environment, overrides, removedNames...)
	case shellPOSIX, shellKsh:
		initFile := filepath.Join(initDirectory, "shrc")
		if err := writeShellInitFile(initFile, posixPromptInit); err != nil {
			launch.cleanup()
			return shellLaunch{}, err
		}
		overrides := []string{
			"ENV=" + initFile,
			"RADOSGW_ASSUME_INIT_DIR=" + initDirectory,
			"RADOSGW_ASSUME_INIT_FILE=" + initFile,
		}
		if originalENV, found := environmentLookup(environment, "ENV"); found {
			overrides = append(overrides,
				"RADOSGW_ASSUME_ORIGINAL_ENV="+originalENV,
				"RADOSGW_ASSUME_ORIGINAL_ENV_SET=1",
			)
			launch.environment = environmentWithOverrides(environment, overrides)
		} else {
			launch.environment = environmentWithOverrides(environment, overrides,
				"RADOSGW_ASSUME_ORIGINAL_ENV", "RADOSGW_ASSUME_ORIGINAL_ENV_SET")
		}
	}

	launch.promptModified = true
	return launch, nil
}

func environmentValue(environment []string, name string) string {
	value, _ := environmentLookup(environment, name)
	return value
}

func environmentLookup(environment []string, name string) (string, bool) {
	for _, variable := range environment {
		variableName, value, found := strings.Cut(variable, "=")
		if found && variableName == name {
			return value, true
		}
	}
	return "", false
}

func writeShellInitFile(path, contents string) error {
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		return fmt.Errorf("write temporary startup file: %w", err)
	}
	return nil
}
