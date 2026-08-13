package main

import (
	"os"

	"golang.org/x/sys/unix"
)

func processIsForeground() bool {
	foregroundGroup, err := unix.IoctlGetInt(int(os.Stdin.Fd()), unix.TIOCGPGRP)
	return err == nil && foregroundGroup == unix.Getpgrp()
}
