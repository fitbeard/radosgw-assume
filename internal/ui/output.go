package ui

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fitbeard/radosgw-assume/internal/config"
)

// shellQuote returns a value that can be safely evaluated by a POSIX shell.
func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

// fprintCredentialExports writes the credential export statements.
func fprintCredentialExports(w io.Writer, result *config.AssumeRoleResult) {
	_, _ = fmt.Fprintf(w, "export AWS_ACCESS_KEY_ID=%s\n", shellQuote(result.AccessKeyID))
	_, _ = fmt.Fprintf(w, "export AWS_SECRET_ACCESS_KEY=%s\n", shellQuote(result.SecretAccessKey))
	_, _ = fmt.Fprintf(w, "export AWS_SESSION_TOKEN=%s\n", shellQuote(result.SessionToken))
	// Don't export fake AWS_PROFILE when using environment variables
	if result.ProfileName != "env" {
		_, _ = fmt.Fprintf(w, "export AWS_PROFILE=%s\n", shellQuote(result.ProfileName))
	}
	_, _ = fmt.Fprintf(w, "export AWS_CREDENTIAL_EXPIRATION=%s\n", shellQuote(result.Expiration))
	_, _ = fmt.Fprintf(w, "export AWS_SESSION_EXPIRATION=%s\n", shellQuote(result.Expiration))
}

// PrintCredentials prints credentials with usage hints (verbose mode)
func PrintCredentials(result *config.AssumeRoleResult) {
	FprintCredentials(os.Stdout, os.Stderr, result)
}

// FprintCredentials writes credentials to stdout and usage hints to stderr.
func FprintCredentials(stdout, stderr io.Writer, result *config.AssumeRoleResult) {
	fprintCredentialExports(stdout, result)

	// Print usage hint to stderr so it doesn't interfere with sourcing
	_, _ = fmt.Fprintf(stderr, "# Credentials exported for profile: %s\n", result.ProfileName)
	_, _ = fmt.Fprintf(stderr, "# Valid until: %s\n", result.Expiration)
	if result.ProfileName != "env" {
		_, _ = fmt.Fprintf(stderr, "# Usage: eval $(radosgw-assume %s)\n", result.ProfileName)
	} else {
		_, _ = fmt.Fprintln(stderr, "# Usage: eval $(radosgw-assume --env)")
	}
	_, _ = fmt.Fprintf(stderr, "# Test with: aws s3 ls --endpoint-url=%s\n", result.EndpointURL)
}

// PrintCredentialsOnly prints credentials without hints (clean mode)
func PrintCredentialsOnly(result *config.AssumeRoleResult) {
	FprintCredentialsOnly(os.Stdout, result)
}

// FprintCredentialsOnly writes credentials without usage hints.
func FprintCredentialsOnly(w io.Writer, result *config.AssumeRoleResult) {
	fprintCredentialExports(w, result)
}
