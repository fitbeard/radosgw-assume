package version

import (
	"fmt"
	"io"
	"os"
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
	FprintVersion(os.Stdout)
}

// FprintVersion writes detailed version information to w.
func FprintVersion(w io.Writer) {
	_, _ = fmt.Fprintf(w, "Version %s\n", Version)
	_, _ = fmt.Fprintf(w, "Git commit: %s\n", GitCommit)
	_, _ = fmt.Fprintf(w, "Build date: %s\n", BuildDate)
	_, _ = fmt.Fprintf(w, "Go version: %s\n", GoVersion)
	_, _ = fmt.Fprintf(w, "Platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
}
