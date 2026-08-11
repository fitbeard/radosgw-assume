package ui

import (
	"fmt"
	"io"
	"os"
)

// PrintUsage displays the help information for the application
func PrintUsage() {
	FprintUsage(os.Stdout)
}

// FprintUsage writes the help information to w.
func FprintUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: radosgw-assume [OPTIONS] [PROFILE]")
	fmt.Fprintln(w, "       radosgw-assume (interactive profile selection)")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Options:")
	fmt.Fprintln(w, "  -h, --help                Show this help message and exit")
	fmt.Fprintln(w, "  -e, --env                 Use environment variables for configuration")
	fmt.Fprintln(w, "  -v, --verbose             Show verbose output with detailed information")
	fmt.Fprintln(w, "  -d, --duration DURATION   Session duration (default: 1h, min: 15m, max: 12h)")
	fmt.Fprintln(w, "                            Formats: '3600' (seconds), '60m' (minutes), '1h' (hours)")
	fmt.Fprintln(w, "  -s, --session NAME        Session name (default: radosgw-assume-TIMESTAMP)")
	fmt.Fprintln(w, "                            Only alphanumeric characters and dashes allowed")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  version                   Show version information")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Arguments:")
	fmt.Fprintln(w, "  PROFILE       Profile name from ~/.aws/config")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  radosgw-assume                        # Interactive selection, clean output")
	fmt.Fprintln(w, "  radosgw-assume myprofile              # Use specific profile, clean output")
	fmt.Fprintln(w, "  radosgw-assume --env                  # Use environment variables")
	fmt.Fprintln(w, "  radosgw-assume -d 2h myprofile        # 2-hour session duration")
	fmt.Fprintln(w, "  radosgw-assume -d 30m myprofile       # 30-minute session duration")
	fmt.Fprintln(w, "  radosgw-assume -d 15m myprofile       # 15-minute session duration (minimum)")
	fmt.Fprintln(w, "  radosgw-assume -s my-session profile  # Custom session name")
	fmt.Fprintln(w, "  eval $(radosgw-assume)                # Interactive with credential export")
	fmt.Fprintln(w, "  eval $(radosgw-assume myprofile)      # Direct profile with export")
	fmt.Fprintln(w, "  radosgw-assume --verbose              # Verbose output with detailed info")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Environment Variables (when using -e/--env):")
	fmt.Fprintln(w, "  RADOSGW_OIDC_PROVIDER      - OIDC provider URL (required, except for token auth)")
	fmt.Fprintln(w, "  RADOSGW_OIDC_CLIENT_ID     - OIDC client ID (required, except for token auth)")
	fmt.Fprintln(w, "  AWS_ENDPOINT_URL           - RadosGW endpoint URL (required)")
	fmt.Fprintln(w, "  RADOSGW_ROLE_ARN           - Role ARN to assume (required)")
	fmt.Fprintln(w, "  RADOSGW_ROLE_SESSION_NAME  - Role session name (optional, default: radosgw-assume-TIMESTAMP)")
	fmt.Fprintln(w, "  RADOSGW_OIDC_AUTH_TYPE     - Auth type: device|browser|token (optional, default: device)")
	fmt.Fprintln(w, "  RADOSGW_OIDC_TOKEN         - Pre-existing OIDC token (required for token auth type)")
	fmt.Fprintln(w, "  RADOSGW_OIDC_SCOPE         - OIDC scope (optional, default: openid, ignored for token auth)")
	fmt.Fprintln(w, "  RADOSGW_OIDC_PKCE_METHOD   - PKCE method: S256|plain (optional, default: S256)")
	fmt.Fprintln(w, "  RADOSGW_SSL_VERIFY         - SSL verification: true|false (optional, default: true)")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Configuration:")
	fmt.Fprintln(w, "  Edit ~/.aws/config with RadosGW and OIDC settings")
	fmt.Fprintln(w, "  See documentation and configuration format details at https://github.com/fitbeard/radosgw-assume")
}
