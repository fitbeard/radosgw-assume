package main

import (
	"fmt"
	"os/exec"
	"syscall"
)

func replaceProcess(command, environment []string) error {
	if len(command) == 0 {
		return fmt.Errorf("cannot execute an empty command")
	}

	path, err := exec.LookPath(command[0])
	if err != nil {
		return fmt.Errorf("find command %q: %w", command[0], err)
	}
	if err := syscall.Exec(path, command, environment); err != nil {
		return fmt.Errorf("execute command %q: %w", command[0], err)
	}

	return nil
}
