package version

import (
	"fmt"
	"runtime"
)

// These variables will be set at build time using ldflags
var (
	Version   = "dev"             // Version number
	GitCommit = "unknown"         // Git commit SHA
	BuildDate = "unknown"         // Build date
	GoVersion = runtime.Version() // Go version used to build
)

// GetVersion returns the version string
func GetVersion() string {
	return Version
}

// GetFullVersion returns a detailed version string
func GetFullVersion() string {
	return fmt.Sprintf("radosgw-assume version %s (commit %s, built %s, %s)",
		Version, GitCommit, BuildDate, GoVersion)
}

// GetUserAgent returns the User-Agent string for HTTP requests
func GetUserAgent() string {
	return fmt.Sprintf("radosgw-assume/%s", Version)
}

// PrintVersion prints the full version information
func PrintVersion() {
	fmt.Printf("Version %s\n", Version)
	fmt.Printf("Git commit: %s\n", GitCommit)
	fmt.Printf("Build date: %s\n", BuildDate)
	fmt.Printf("Go version: %s\n", GoVersion)
	fmt.Printf("Platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
}
