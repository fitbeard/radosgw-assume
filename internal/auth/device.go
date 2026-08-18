package auth

import (
	"context"
	"io"
	"os"
)

// AuthenticateDeviceFlow performs OIDC device flow authentication with PKCE.
func AuthenticateDeviceFlow(ctx context.Context, options OIDCOptions) (string, error) {
	return AuthenticateDeviceFlowWithOutput(ctx, options, os.Stderr)
}

// AuthenticateDeviceFlowWithOutput performs OIDC device flow authentication
// and writes user interaction to output.
func AuthenticateDeviceFlowWithOutput(ctx context.Context, options OIDCOptions, output io.Writer) (string, error) {
	dependencies := newDeviceFlowDependencies()
	dependencies.stderr = output
	dependencies.newProgress = func() deviceFlowProgress { return newProgressIndicatorWithOutput(output) }
	return authenticateDeviceFlow(ctx, options, dependencies)
}
