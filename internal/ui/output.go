package ui

import (
	"fmt"
	"os"
	"strings"

	"github.com/fitbeard/radosgw-assume/internal/config"
)

// shellQuote returns a value that can be safely evaluated by a POSIX shell.
func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

// printCredentialExports prints the credential export statements
func printCredentialExports(result *config.AssumeRoleResult) {
	fmt.Printf("export AWS_ACCESS_KEY_ID=%s\n", shellQuote(result.AccessKeyID))
	fmt.Printf("export AWS_SECRET_ACCESS_KEY=%s\n", shellQuote(result.SecretAccessKey))
	fmt.Printf("export AWS_SESSION_TOKEN=%s\n", shellQuote(result.SessionToken))
	// Don't export fake AWS_PROFILE when using environment variables
	if result.ProfileName != "env" {
		fmt.Printf("export AWS_PROFILE=%s\n", shellQuote(result.ProfileName))
	}
	fmt.Printf("export AWS_CREDENTIAL_EXPIRATION=%s\n", shellQuote(result.Expiration))
	fmt.Printf("export AWS_SESSION_EXPIRATION=%s\n", shellQuote(result.Expiration))
}

// PrintCredentials prints credentials with usage hints (verbose mode)
func PrintCredentials(result *config.AssumeRoleResult) {
	printCredentialExports(result)

	// Print usage hint to stderr so it doesn't interfere with sourcing
	fmt.Fprintf(os.Stderr, "# Credentials exported for profile: %s\n", result.ProfileName)
	fmt.Fprintf(os.Stderr, "# Valid until: %s\n", result.Expiration)
	if result.ProfileName != "env" {
		fmt.Fprintf(os.Stderr, "# Usage: eval $(radosgw-assume %s)\n", result.ProfileName)
	} else {
		fmt.Fprintf(os.Stderr, "# Usage: eval $(radosgw-assume --env)\n")
	}
	fmt.Fprintf(os.Stderr, "# Test with: aws s3 ls --endpoint-url=%s\n", result.EndpointURL)
}

// PrintCredentialsOnly prints credentials without hints (clean mode)
func PrintCredentialsOnly(result *config.AssumeRoleResult) {
	printCredentialExports(result)
}
