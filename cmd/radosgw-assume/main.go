package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	runner := newCLIRunner(os.Stdout, os.Stderr)
	exitCode := runner.runContext(ctx, os.Args[0], os.Args[1:])
	stop()
	os.Exit(exitCode)
}
