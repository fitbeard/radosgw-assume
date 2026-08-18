package main

import "path/filepath"

type shellKind int

const (
	shellUnknown shellKind = iota
	shellBash
	shellZsh
	shellPOSIX
	shellKsh
	shellFish
)

func detectShell(shell string) shellKind {
	switch filepath.Base(shell) {
	case "bash":
		return shellBash
	case "zsh":
		return shellZsh
	case "sh", "ash", "dash":
		return shellPOSIX
	case "ksh", "ksh93", "mksh", "pdksh":
		return shellKsh
	case "fish":
		return shellFish
	default:
		return shellUnknown
	}
}
