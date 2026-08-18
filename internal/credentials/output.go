package credentials

import (
	"fmt"
	"io"
	"time"

	"github.com/fitbeard/radosgw-assume/pkg/duration"
)

func printCredentialContext(stderr io.Writer, profileName string, resolvedConfig *resolvedCredentialConfig, verboseMode bool, sessionDuration time.Duration) {
	verbosef(stderr, verboseMode, "# Using profile: %s\n", profileName)
	verbosef(stderr, verboseMode, "# RadosGW endpoint: %s\n", resolvedConfig.sourceConfig.EndpointURL)
	if resolvedConfig.authType != "token" {
		verbosef(stderr, verboseMode, "# OIDC provider: %s\n", resolvedConfig.sourceConfig.RadosGWOIDCProvider)
	}
	verbosef(stderr, verboseMode, "# Auth type: %s\n", resolvedConfig.authType)
	verbosef(stderr, verboseMode, "# Session duration: %d seconds (%s)\n", int(sessionDuration.Seconds()), duration.Format(sessionDuration))
}

func verbosef(w io.Writer, enabled bool, format string, args ...any) {
	if enabled {
		_, _ = fmt.Fprintf(w, format, args...)
	}
}
