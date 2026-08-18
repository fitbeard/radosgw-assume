package auth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

type browserFlowTimer interface {
	Done() <-chan time.Time
	Stop()
}

type browserFlowProgress interface {
	Stop()
	StopQuiet()
}

type browserFlowDependencies struct {
	stderr io.Writer

	generateRandomString func(int) (string, error)
	generatePKCE         func(string) (string, string, string, error)
	startCallbackServer  func(chan<- browserCallbackResult) (*browserCallbackServer, error)
	openBrowser          func(string) error
	newHTTPClient        func(bool) *http.Client
	discoverEndpoints    func(context.Context, *http.Client, string) (oidcEndpoints, error)
	newTimer             func(time.Duration) browserFlowTimer
	newProgress          func() browserFlowProgress
}

type realBrowserFlowTimer struct {
	timer *time.Timer
}

func (timer *realBrowserFlowTimer) Done() <-chan time.Time {
	return timer.timer.C
}

func (timer *realBrowserFlowTimer) Stop() {
	timer.timer.Stop()
}

func newBrowserFlowDependencies() browserFlowDependencies {
	return browserFlowDependencies{
		stderr:               os.Stderr,
		generateRandomString: GenerateRandomString,
		generatePKCE:         GeneratePKCE,
		startCallbackServer: func(results chan<- browserCallbackResult) (*browserCallbackServer, error) {
			return startBrowserCallbackServer(
				callbackListenHost,
				[]int{CallbackPort, CallbackFallbackPort},
				results,
			)
		},
		openBrowser:       openBrowser,
		newHTTPClient:     NewHTTPClient,
		discoverEndpoints: discoverOIDCEndpoints,
		newTimer: func(timeout time.Duration) browserFlowTimer {
			return &realBrowserFlowTimer{timer: time.NewTimer(timeout)}
		},
		newProgress: func() browserFlowProgress { return NewProgressIndicator() },
	}
}

// AuthenticateBrowserFlow performs OIDC authorization code flow with PKCE.
func AuthenticateBrowserFlow(ctx context.Context, providerURL, clientID, scope, pkceMethod string, sslVerify bool, verboseMode bool) (string, error) {
	return AuthenticateBrowserFlowWithOutput(ctx, providerURL, clientID, scope, pkceMethod, sslVerify, verboseMode, os.Stderr)
}

// AuthenticateBrowserFlowWithOutput performs OIDC authorization code flow
// authentication and writes user interaction to output.
func AuthenticateBrowserFlowWithOutput(ctx context.Context, providerURL, clientID, scope, pkceMethod string, sslVerify bool, verboseMode bool, output io.Writer) (string, error) {
	dependencies := newBrowserFlowDependencies()
	dependencies.stderr = output
	dependencies.newProgress = func() browserFlowProgress { return newProgressIndicatorWithOutput(output) }
	return authenticateBrowserFlow(
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

func authenticateBrowserFlow(ctx context.Context, providerURL, clientID, scope, pkceMethod string, sslVerify bool, verboseMode bool, dependencies browserFlowDependencies) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	state, err := dependencies.generateRandomString(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
	}
	codeVerifier, codeChallenge, resolvedPKCEMethod, err := dependencies.generatePKCE(pkceMethod)
	if err != nil {
		return "", err
	}
	client := dependencies.newHTTPClient(sslVerify)
	endpoints, err := dependencies.discoverEndpoints(ctx, client, providerURL)
	if err != nil {
		return "", err
	}
	if err := endpoints.validateBrowserFlow(); err != nil {
		return "", err
	}

	callbackResults := make(chan browserCallbackResult, 1)
	callbackServer, err := dependencies.startCallbackServer(callbackResults)
	if err != nil {
		return "", fmt.Errorf("both callback ports (%d and %d) are in use, please free one of them: %w", CallbackPort, CallbackFallbackPort, err)
	}
	defer func() { _ = callbackServer.close() }()

	if callbackServer.port == CallbackFallbackPort && verboseMode {
		_, _ = fmt.Fprintf(dependencies.stderr, "# Port %d is busy, using fallback port %d...\n", CallbackPort, CallbackFallbackPort)
	}

	redirectURI := fmt.Sprintf("http://localhost:%d/callback", callbackServer.port)
	authURL := buildBrowserAuthorizationURL(
		endpoints.authorization,
		clientID,
		redirectURI,
		scope,
		state,
		codeChallenge,
		resolvedPKCEMethod,
	)

	printBrowserAuthenticationInstructions(dependencies.stderr, authURL)
	if err := dependencies.openBrowser(authURL); err != nil {
		_, _ = fmt.Fprintf(dependencies.stderr, "# ⚠ Could not open browser automatically: %v\n", err)
		_, _ = fmt.Fprintln(dependencies.stderr, "#")
		_, _ = fmt.Fprintln(dependencies.stderr, "# 📋 Please manually open this URL in your browser:")
		_, _ = fmt.Fprintf(dependencies.stderr, "# %s\n", authURL)
	} else {
		_, _ = fmt.Fprintln(dependencies.stderr, "# ✓ Browser opened successfully")
	}
	printBrowserAuthenticationWait(dependencies.stderr)

	// Wait for callback with timeout.
	timeout := dependencies.newTimer(AuthTimeout)
	defer timeout.Stop()

	// Progress indication
	progress := dependencies.newProgress()

	var callbackResult browserCallbackResult
	select {
	case callbackResult = <-callbackResults:
		// Callback received
		progress.Stop()
	case err := <-callbackServer.errors:
		progress.StopQuiet()
		return "", fmt.Errorf("callback server failed: %w", err)
	case <-timeout.Done():
		progress.StopQuiet()
		return "", fmt.Errorf("authentication timed out after %v", AuthTimeout)
	case <-ctx.Done():
		progress.StopQuiet()
		return "", ctx.Err()
	}

	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), CallbackShutdownTimeout)
	defer cancelShutdown()
	if err := callbackServer.shutdown(shutdownContext); err != nil {
		return "", fmt.Errorf("failed to stop callback server: %w", err)
	}

	if callbackResult.errorCode != "" {
		return "", FormatOIDCError(callbackResult.errorCode, callbackResult.errorDescription, providerURL)
	}

	if callbackResult.code == "" {
		return "", fmt.Errorf("no authorization code received")
	}

	// Validate state parameter
	if callbackResult.state != state {
		return "", fmt.Errorf("security error: state parameter mismatch")
	}

	if verboseMode {
		_, _ = fmt.Fprintln(dependencies.stderr, "# ✓ Authentication successful!")
		_, _ = fmt.Fprintln(dependencies.stderr, "# Exchanging authorization code for tokens...")
	}

	tokenData := url.Values{}
	tokenData.Set("grant_type", "authorization_code")
	tokenData.Set("client_id", clientID)
	tokenData.Set("code", callbackResult.code)
	tokenData.Set("redirect_uri", redirectURI)
	tokenData.Set("code_verifier", codeVerifier)

	accessToken, err := exchangeBrowserAuthorizationCode(
		ctx,
		client,
		endpoints.token,
		tokenData,
		providerURL,
	)
	if err != nil {
		return "", err
	}

	if verboseMode {
		_, _ = fmt.Fprintln(dependencies.stderr, "# ✓ Successfully obtained access token")
	}

	return accessToken, nil
}

func buildBrowserAuthorizationURL(authEndpoint, clientID, redirectURI, scope, state, codeChallenge, pkceMethod string) string {
	authURL, err := url.Parse(authEndpoint)
	if err != nil {
		return authEndpoint
	}
	authParams := authURL.Query()
	authParams.Set("client_id", clientID)
	authParams.Set("redirect_uri", redirectURI)
	authParams.Set("response_type", "code")
	authParams.Set("scope", scope)
	authParams.Set("state", state)
	authParams.Set("code_challenge", codeChallenge)
	authParams.Set("code_challenge_method", pkceMethod)
	authURL.RawQuery = authParams.Encode()
	return authURL.String()
}

func printBrowserAuthenticationInstructions(stderr io.Writer, authURL string) {
	_, _ = fmt.Fprintln(stderr, "#")
	_, _ = fmt.Fprintln(stderr, "# 🔐 BROWSER AUTHENTICATION REQUIRED")
	_, _ = fmt.Fprintln(stderr, "#")
	_, _ = fmt.Fprintf(stderr, "# Auth URL: %s\n", authURL)
	_, _ = fmt.Fprintln(stderr, "# Opening browser for authentication...")
}

func printBrowserAuthenticationWait(stderr io.Writer) {
	_, _ = fmt.Fprintln(stderr, "#")
	_, _ = fmt.Fprintln(stderr, "# ⏰ You have 60 seconds to complete authentication")
	_, _ = fmt.Fprintln(stderr, "#")
	_, _ = fmt.Fprintln(stderr, "# Waiting for authentication...")
}

func exchangeBrowserAuthorizationCode(ctx context.Context, client *http.Client, tokenEndpoint string, tokenData url.Values, providerURL string) (string, error) {
	response, err := postOIDCForm(ctx, client, tokenEndpoint, tokenData)
	if err != nil {
		return "", fmt.Errorf("token exchange failed: %w", err)
	}
	body, err := readOIDCResponseAndClose(response)
	if err != nil {
		return "", fmt.Errorf("failed to read token response: %w", err)
	}

	tokenResponse, err := decodeOIDCTokenResponse("token exchange", response.StatusCode, body, providerURL)
	if err != nil {
		return "", err
	}

	if response.StatusCode != http.StatusOK {
		return "", oidcHTTPStatusError("token exchange", response.StatusCode, body, providerURL)
	}

	return accessTokenFromOIDCResponse(tokenResponse, providerURL)
}
