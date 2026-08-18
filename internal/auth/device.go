package auth

import (
	"context"
	"io"
	"os"
)

// AuthenticateDeviceFlow performs OIDC device flow authentication with PKCE.
func AuthenticateDeviceFlow(ctx context.Context, providerURL, clientID, scope, pkceMethod string, sslVerify bool, verboseMode bool) (string, error) {
	return AuthenticateDeviceFlowWithOutput(ctx, providerURL, clientID, scope, pkceMethod, sslVerify, verboseMode, os.Stderr)
}

// AuthenticateDeviceFlowWithOutput performs OIDC device flow authentication
// and writes user interaction to output.
func AuthenticateDeviceFlowWithOutput(ctx context.Context, providerURL, clientID, scope, pkceMethod string, sslVerify bool, verboseMode bool, output io.Writer) (string, error) {
	dependencies := newDeviceFlowDependencies()
	dependencies.stderr = output
	dependencies.newProgress = func() deviceFlowProgress { return newProgressIndicatorWithOutput(output) }
	return authenticateDeviceFlow(
		ctx,
		providerURL,
		clientID,
		scope,
		pkceMethod,
		sslVerify,
		verboseMode,
		dependencies,
	)
}
