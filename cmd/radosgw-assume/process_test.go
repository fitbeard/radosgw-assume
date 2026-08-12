package main

import (
	"bytes"
	"errors"
	"os"
	osexec "os/exec"
	"strings"
	"syscall"
	"testing"
)

const execHelperModeEnvironment = "RADOSGW_ASSUME_EXEC_HELPER_MODE"

func TestReplaceProcessHelper(t *testing.T) {
	mode := os.Getenv(execHelperModeEnvironment)
	if mode == "" {
		return
	}

	var command []string
	environment := os.Environ()
	switch mode {
	case "stdio":
		command = []string{
			"sh",
			"-c",
			`read -r line; printf '%s:%s:%s' "$RADOSGW_ASSUME_EXEC_TEST_VALUE" "$line" "$1"`,
			"exec-test",
			"argument-value",
		}
		environment = append(environment, "RADOSGW_ASSUME_EXEC_TEST_VALUE=environment-value")
	case "exit":
		command = []string{"sh", "-c", "exit 23"}
	case "signal":
		command = []string{"sh", "-c", "kill -TERM $$"}
	default:
		t.Fatalf("unknown helper mode %q", mode)
	}

	if err := replaceProcess(command, environment); err != nil {
		t.Fatalf("replaceProcess() error = %v", err)
	}
	t.Fatal("replaceProcess() unexpectedly returned")
}

func TestReplaceProcessPreservesEnvironmentArgumentsAndIO(t *testing.T) {
	command := newExecHelperCommand("stdio")
	command.Stdin = strings.NewReader("input-value\n")
	var stdout bytes.Buffer
	command.Stdout = &stdout

	if err := command.Run(); err != nil {
		t.Fatalf("exec helper error = %v", err)
	}
	if got := stdout.String(); got != "environment-value:input-value:argument-value" {
		t.Errorf("exec helper output = %q", got)
	}
}

func TestReplaceProcessPreservesExitCode(t *testing.T) {
	err := newExecHelperCommand("exit").Run()
	var exitError *osexec.ExitError
	if !errors.As(err, &exitError) {
		t.Fatalf("exec helper error = %v, want *exec.ExitError", err)
	}
	if exitError.ExitCode() != 23 {
		t.Errorf("exec helper exit code = %d, want 23", exitError.ExitCode())
	}
}

func TestReplaceProcessPreservesSignal(t *testing.T) {
	err := newExecHelperCommand("signal").Run()
	var exitError *osexec.ExitError
	if !errors.As(err, &exitError) {
		t.Fatalf("exec helper error = %v, want *exec.ExitError", err)
	}
	waitStatus, ok := exitError.Sys().(syscall.WaitStatus)
	if !ok {
		t.Fatalf("exec helper status = %T, want syscall.WaitStatus", exitError.Sys())
	}
	if !waitStatus.Signaled() || waitStatus.Signal() != syscall.SIGTERM {
		t.Errorf("exec helper signal status = %v, want %v", waitStatus, syscall.SIGTERM)
	}
}

func TestReplaceProcessErrors(t *testing.T) {
	if err := replaceProcess(nil, os.Environ()); err == nil || !strings.Contains(err.Error(), "empty command") {
		t.Errorf("replaceProcess(nil) error = %v", err)
	}

	command := []string{"radosgw-assume-command-that-does-not-exist"}
	if err := replaceProcess(command, os.Environ()); err == nil || !strings.Contains(err.Error(), `find command "radosgw-assume-command-that-does-not-exist"`) {
		t.Errorf("replaceProcess(nonexistent) error = %v", err)
	}
}

func newExecHelperCommand(mode string) *osexec.Cmd {
	command := osexec.Command(os.Args[0], "-test.run=^TestReplaceProcessHelper$")
	command.Env = append(os.Environ(), execHelperModeEnvironment+"="+mode)
	return command
}
