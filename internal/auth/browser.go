package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"time"
)

const callbackListenHost = "127.0.0.1"

type browserCallbackResult struct {
	code             string
	state            string
	errorCode        string
	errorDescription string
}

// AuthenticateBrowserFlow performs OIDC authorization code flow with PKCE.
func AuthenticateBrowserFlow(providerURL, clientID, scope, pkceMethod string, sslVerify bool, verboseMode bool) (string, error) {
	tokenEndpoint := fmt.Sprintf("%s/protocol/openid-connect/token", providerURL)
	authEndpoint := fmt.Sprintf("%s/protocol/openid-connect/auth", providerURL)

	state, err := GenerateRandomString(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
	}
	codeVerifier, codeChallenge, resolvedPKCEMethod, err := GeneratePKCE(pkceMethod)
	if err != nil {
		return "", err
	}

	callbackResults := make(chan browserCallbackResult, 1)
	listener, callbackPort, err := listenOnCallbackPorts(callbackListenHost, CallbackPort, CallbackFallbackPort)
	if err != nil {
		return "", fmt.Errorf("both callback ports (%d and %d) are in use, please free one of them: %w", CallbackPort, CallbackFallbackPort, err)
	}
	if callbackPort == CallbackFallbackPort && verboseMode {
		fmt.Fprintf(os.Stderr, "# Port %d is busy, using fallback port %d...\n", CallbackPort, CallbackFallbackPort)
	}

	redirectURI := fmt.Sprintf("http://localhost:%d/callback", callbackPort)
	server := &http.Server{
		Handler:           newBrowserCallbackHandler(callbackResults),
		ReadHeaderTimeout: CallbackReadHeaderTimeout,
	}

	// The listener is already bound, so another process cannot claim the port
	// between availability detection and Serve.
	serverError := make(chan error, 1)
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverError <- err
		}
	}()
	defer func() { _ = server.Close() }()

	// Build authorization URL
	authParams := url.Values{}
	authParams.Set("client_id", clientID)
	authParams.Set("redirect_uri", redirectURI)
	authParams.Set("response_type", "code")
	authParams.Set("scope", scope)
	authParams.Set("state", state)
	authParams.Set("code_challenge", codeChallenge)
	authParams.Set("code_challenge_method", resolvedPKCEMethod)

	authURL := authEndpoint + "?" + authParams.Encode()

	fmt.Fprintf(os.Stderr, "#\n")
	fmt.Fprintf(os.Stderr, "# 🔐 BROWSER AUTHENTICATION REQUIRED\n")
	fmt.Fprintf(os.Stderr, "#\n")
	fmt.Fprintf(os.Stderr, "# Auth URL: %s\n", authURL)
	fmt.Fprintf(os.Stderr, "# Opening browser for authentication...\n")

	// Try to open browser
	if err := openBrowser(authURL); err != nil {
		fmt.Fprintf(os.Stderr, "# ⚠ Could not open browser automatically: %v\n", err)
		fmt.Fprintf(os.Stderr, "#\n")
		fmt.Fprintf(os.Stderr, "# 📋 Please manually open this URL in your browser:\n")
		fmt.Fprintf(os.Stderr, "# %s\n", authURL)
	} else {
		fmt.Fprintf(os.Stderr, "# ✓ Browser opened successfully\n")
	}

	fmt.Fprintf(os.Stderr, "#\n")
	fmt.Fprintf(os.Stderr, "# ⏰ You have 60 seconds to complete authentication\n")
	fmt.Fprintf(os.Stderr, "#\n")
	fmt.Fprintf(os.Stderr, "# Waiting for authentication...\n")

	// Wait for callback with timeout.
	timeout := time.NewTimer(AuthTimeout)
	defer timeout.Stop()

	// Progress indication
	progress := NewProgressIndicator()

	var callbackResult browserCallbackResult
	select {
	case callbackResult = <-callbackResults:
		// Callback received
		progress.Stop()
	case err := <-serverError:
		progress.StopQuiet()
		return "", fmt.Errorf("callback server failed: %w", err)
	case <-timeout.C:
		progress.StopQuiet()
		return "", fmt.Errorf("authentication timed out after %v", AuthTimeout)
	}

	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), CallbackShutdownTimeout)
	defer cancelShutdown()
	if err := server.Shutdown(shutdownContext); err != nil {
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
		fmt.Fprintf(os.Stderr, "# ✓ Authentication successful!\n")
	}

	// Exchange authorization code for tokens
	if verboseMode {
		fmt.Fprintf(os.Stderr, "# Exchanging authorization code for tokens...\n")
	}

	tokenData := url.Values{}
	tokenData.Set("grant_type", "authorization_code")
	tokenData.Set("client_id", clientID)
	tokenData.Set("code", callbackResult.code)
	tokenData.Set("redirect_uri", redirectURI)
	tokenData.Set("code_verifier", codeVerifier)

	client := NewHTTPClient(sslVerify)

	resp, err := client.PostForm(tokenEndpoint, tokenData)
	if err != nil {
		return "", fmt.Errorf("token exchange failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResponse TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return "", fmt.Errorf("failed to parse token response: %w", err)
	}

	if tokenResponse.Error != "" {
		return "", FormatOIDCError(tokenResponse.Error, tokenResponse.ErrorDesc, providerURL)
	}

	if tokenResponse.AccessToken == "" {
		return "", fmt.Errorf("no access token received")
	}

	if verboseMode {
		fmt.Fprintf(os.Stderr, "# ✓ Successfully obtained access token\n")
	}

	return tokenResponse.AccessToken, nil
}

func listenOnCallbackPorts(host string, ports ...int) (net.Listener, int, error) {
	if len(ports) == 0 {
		return nil, 0, fmt.Errorf("no callback ports configured")
	}

	var listenErrors []error
	for _, port := range ports {
		listener, err := net.Listen("tcp4", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			listenErrors = append(listenErrors, fmt.Errorf("port %d: %w", port, err))
			continue
		}

		boundPort := listener.Addr().(*net.TCPAddr).Port
		return listener, boundPort, nil
	}

	return nil, 0, errors.Join(listenErrors...)
}

func newBrowserCallbackHandler(results chan<- browserCallbackResult) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()

		if errorCode := query.Get("error"); errorCode != "" {
			errorDescription := query.Get("error_description")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintf(w, `
			<html lang="en">
			<head>
				<meta charset="UTF-8">
				<title>Authentication Failed</title>
				<style>
					body {
						background-color: #eee;
						margin: 0;
						padding: 0;
						font-family: sans-serif;
					}
					.placeholder {
						margin: 2em;
						padding: 2em;
						background-color: #fff;
						border-radius: 1em;
					}
				</style>
			</head>
			<body>
				<div class="placeholder">
					<h1>Authentication Failed</h1>
					<p>Error: %s</p>
					<p>Description: %s</p>
					<p>You can close this window and try again.</p>
				</div>
			</body>
			</html>
			`, html.EscapeString(errorCode), html.EscapeString(errorDescription))
			deliverBrowserCallbackResult(results, browserCallbackResult{
				errorCode:        errorCode,
				errorDescription: errorDescription,
			})
			return
		}

		code := query.Get("code")
		state := query.Get("state")
		if code == "" || state == "" {
			http.Error(w, "missing code or state", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, `
			<html lang="en">
			<head>
				<meta charset="UTF-8">
				<title>Authentication Successful</title>
				<script>setTimeout(function(){window.close()}, 3000);</script>
				<style>
					body {
						background-color: #eee;
						margin: 0;
						padding: 0;
						font-family: sans-serif;
					}
					.placeholder {
						margin: 2em;
						padding: 2em;
						background-color: #fff;
						border-radius: 1em;
					}
				</style>
			</head>
			<body>
				<div class="placeholder">
					<h1>Authentication Successful</h1>
					<p>You have successfully authenticated with RadosGW. You can now close this window and return to your terminal.</p>
				</div>
			</body>
			</html>
			`)
		deliverBrowserCallbackResult(results, browserCallbackResult{code: code, state: state})
	})

	return mux
}

func deliverBrowserCallbackResult(results chan<- browserCallbackResult, result browserCallbackResult) {
	select {
	case results <- result:
	default:
		// A callback has already completed the flow. Never block a duplicate or
		// late browser request while the server is shutting down.
	}
}

func openBrowser(url string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start"}
	case "darwin":
		cmd = "open"
	default: // "linux", "freebsd", "openbsd", "netbsd"
		cmd = "xdg-open"
	}
	args = append(args, url)
	return exec.Command(cmd, args...).Start()
}
