package main

import (
	"os"
)

func main() {
	runner := newCLIRunner(os.Stdout, os.Stderr)
	os.Exit(runner.run(os.Args[0], os.Args[1:]))
}
