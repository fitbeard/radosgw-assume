package auth

import (
	"fmt"
	"io"
	"time"

	"github.com/fitbeard/radosgw-assume/pkg/duration"
)

func printDeviceAuthenticationInstructions(stderr io.Writer, response DeviceAuthResponse) {
	_, _ = fmt.Fprintln(stderr, "#")
	_, _ = fmt.Fprintln(stderr, "# 🔐 AUTHENTICATION REQUIRED")
	_, _ = fmt.Fprintln(stderr, "#")
	_, _ = fmt.Fprintln(stderr, "# Please authenticate using your browser:")
	_, _ = fmt.Fprintln(stderr, "#")
	_, _ = fmt.Fprintf(stderr, "# 1. Open this URL: %s\n", response.VerificationURI)
	_, _ = fmt.Fprintf(stderr, "# 2. Enter this code: %s\n", response.UserCode)
	if response.VerificationURIComplete != "" {
		_, _ = fmt.Fprintln(stderr, "#")
		_, _ = fmt.Fprintf(stderr, "#    OR use this direct link: %s\n", response.VerificationURIComplete)
	}
	_, _ = fmt.Fprintln(stderr, "#")
	lifetime := time.Duration(response.ExpiresIn) * time.Second
	_, _ = fmt.Fprintf(stderr, "# ⏰ You have %d seconds (%s) to complete authentication\n", response.ExpiresIn, duration.Format(lifetime))
	_, _ = fmt.Fprintln(stderr, "#")
	_, _ = fmt.Fprintln(stderr, "# Waiting for authentication...")
}
