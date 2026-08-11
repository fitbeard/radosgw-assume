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
	_, _ = fmt.Fprintln(w, "Usage: radosgw-assume [OPTIONS] [PROFILE]")
	_, _ = fmt.Fprintln(w, "       radosgw-assume (interactive profile selection)")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "Options:")
	_, _ = fmt.Fprintln(w, "  -h, --help                Show this help message and exit")
	_, _ = fmt.Fprintln(w, "  -e, --env                 Use environment variables for configuration")
	_, _ = fmt.Fprintln(w, "  -v, --verbose             Show verbose output with detailed information")
	_, _ = fmt.Fprintln(w, "  -d, --duration DURATION   Session duration (default: 1h, min: 15m, max: 12h)")
	_, _ = fmt.Fprintln(w, "                            Formats: '3600' (seconds), '60m' (minutes), '1h' (hours)")
	_, _ = fmt.Fprintln(w, "  -s, --session NAME        Session name (default: radosgw-assume-TIMESTAMP)")
	_, _ = fmt.Fprintln(w, "                            Only alphanumeric characters and dashes allowed")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "Commands:")
	_, _ = fmt.Fprintln(w, "  version                   Show version information")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "Arguments:")
	_, _ = fmt.Fprintln(w, "  PROFILE       Profile name from ~/.aws/config")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "Examples:")
	_, _ = fmt.Fprintln(w, "  radosgw-assume                        # Interactive selection, clean output")
	_, _ = fmt.Fprintln(w, "  radosgw-assume myprofile              # Use specific profile, clean output")
	_, _ = fmt.Fprintln(w, "  radosgw-assume --env                  # Use environment variables")
	_, _ = fmt.Fprintln(w, "  radosgw-assume -d 2h myprofile        # 2-hour session duration")
	_, _ = fmt.Fprintln(w, "  radosgw-assume -d 30m myprofile       # 30-minute session duration")
	_, _ = fmt.Fprintln(w, "  radosgw-assume -d 15m myprofile       # 15-minute session duration (minimum)")
	_, _ = fmt.Fprintln(w, "  radosgw-assume -s my-session profile  # Custom session name")
	_, _ = fmt.Fprintln(w, "  eval $(radosgw-assume)                # Interactive with credential export")
	_, _ = fmt.Fprintln(w, "  eval $(radosgw-assume myprofile)      # Direct profile with export")
	_, _ = fmt.Fprintln(w, "  radosgw-assume --verbose              # Verbose output with detailed info")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "Environment Variables (when using -e/--env):")
	_, _ = fmt.Fprintln(w, "  RADOSGW_OIDC_PROVIDER      - OIDC provider URL (required, except for token auth)")
	_, _ = fmt.Fprintln(w, "  RADOSGW_OIDC_CLIENT_ID     - OIDC client ID (required, except for token auth)")
	_, _ = fmt.Fprintln(w, "  AWS_ENDPOINT_URL           - RadosGW endpoint URL (required)")
	_, _ = fmt.Fprintln(w, "  RADOSGW_ROLE_ARN           - Role ARN to assume (required)")
	_, _ = fmt.Fprintln(w, "  RADOSGW_ROLE_SESSION_NAME  - Role session name (optional, default: radosgw-assume-TIMESTAMP)")
	_, _ = fmt.Fprintln(w, "  RADOSGW_OIDC_AUTH_TYPE     - Auth type: device|browser|token (optional, default: device)")
	_, _ = fmt.Fprintln(w, "  RADOSGW_OIDC_TOKEN         - Pre-existing OIDC token (required for token auth type)")
	_, _ = fmt.Fprintln(w, "  RADOSGW_OIDC_SCOPE         - OIDC scope (optional, default: openid, ignored for token auth)")
	_, _ = fmt.Fprintln(w, "  RADOSGW_OIDC_PKCE_METHOD   - PKCE method: S256|plain (optional, default: S256)")
	_, _ = fmt.Fprintln(w, "  RADOSGW_SSL_VERIFY         - SSL verification: true|false (optional, default: true)")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "Configuration:")
	_, _ = fmt.Fprintln(w, "  Edit ~/.aws/config with RadosGW and OIDC settings")
	_, _ = fmt.Fprintln(w, "  See documentation and configuration format details at https://github.com/fitbeard/radosgw-assume")
}
