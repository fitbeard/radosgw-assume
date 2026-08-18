package main

import (
	"path/filepath"
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
