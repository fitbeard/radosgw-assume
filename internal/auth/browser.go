package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"time"
)

// AuthenticateBrowserFlow performs OIDC authorization code flow with PKCE
func AuthenticateBrowserFlow(providerURL, clientID, scope string, sslVerify bool, verboseMode bool) (string, error) {
	tokenEndpoint := fmt.Sprintf("%s/protocol/openid-connect/token", providerURL)
	authEndpoint := fmt.Sprintf("%s/protocol/openid-connect/auth", providerURL)

	// OAuth2/PKCE setup
	var redirectURI string
	var server *http.Server
	port := 8080
	fallbackPort := 18088

	// Try primary port first, fallback to alternative if busy
	for _, tryPort := range []int{port, fallbackPort} {
		redirectURI = fmt.Sprintf("http://localhost:%d/callback", tryPort)
		server = &http.Server{Addr: fmt.Sprintf(":%d", tryPort)}

		// Test if port is available
		if err := testPortAvailability(tryPort); err == nil {
			break
		} else if tryPort == fallbackPort {
			// Both ports failed
			return "", fmt.Errorf("both callback ports (8080 and 18088) are in use, please free one of them")
		}
		if verboseMode {
			fmt.Fprintf(os.Stderr, "# Port %d is busy, trying fallback port %d...\n", tryPort, fallbackPort)
		}
	}

	state := generateRandomString(32)
	codeVerifier := generateRandomString(96)

	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash[:])

	// Set up callback server
	authCode := ""
	authState := ""
	callbackError := ""
	done := make(chan bool)

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()

		if errParam := query.Get("error"); errParam != "" {
			callbackError = errParam
			errorDesc := query.Get("error_description")

			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(400)
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
			`, errParam, errorDesc)
			done <- true
			return
		}

		code := query.Get("code")
		receivedState := query.Get("state")

		if code != "" && receivedState != "" {
			authCode = code
			authState = receivedState

		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, `
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
			done <- true
		}
	})

	server.Handler = mux

	// Start local server
	serverError := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverError <- err
		}
	}()

	// Give server a moment to start
	select {
	case err := <-serverError:
		return "", err
	case <-time.After(200 * time.Millisecond):
		// Server started successfully
	}

	// Build authorization URL
	authParams := url.Values{}
	authParams.Set("client_id", clientID)
	authParams.Set("redirect_uri", redirectURI)
	authParams.Set("response_type", "code")
	authParams.Set("scope", scope)
	authParams.Set("state", state)
	authParams.Set("code_challenge", codeChallenge)
	authParams.Set("code_challenge_method", "S256")

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

	// Wait for callback with timeout
	timeout := time.After(60 * time.Second)

	// Progress indication
	progressTicker := time.NewTicker(5 * time.Second)
	defer progressTicker.Stop()

	progressDone := make(chan bool)
	go func() {
		for {
			select {
			case <-progressTicker.C:
				fmt.Fprintf(os.Stderr, "#")
			case <-progressDone:
				return
			}
		}
	}()

	select {
	case <-done:
		// Callback received
		progressDone <- true
	case <-timeout:
		progressDone <- true
		_ = server.Shutdown(context.Background())
		return "", fmt.Errorf("authentication timed out")
	}

	fmt.Fprintf(os.Stderr, "\n") // New line after progress dots

	// Shutdown server
	_ = server.Shutdown(context.Background())

	if callbackError != "" {
		return "", fmt.Errorf("authentication failed: %s", callbackError)
	}

	if authCode == "" {
		return "", fmt.Errorf("no authorization code received")
	}

	// Validate state parameter
	if authState != state {
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
	tokenData.Set("code", authCode)
	tokenData.Set("redirect_uri", redirectURI)
	tokenData.Set("code_verifier", codeVerifier)

	client := &http.Client{}
	if !sslVerify {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

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
		return "", fmt.Errorf("token exchange failed: %s - %s", tokenResponse.Error, tokenResponse.ErrorDesc)
	}

	if tokenResponse.AccessToken == "" {
		return "", fmt.Errorf("no access token received")
	}

	if verboseMode {
		fmt.Fprintf(os.Stderr, "# ✓ Successfully obtained access token\n")
	}

	return tokenResponse.AccessToken, nil
}

// Helper functions
func testPortAvailability(port int) error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}
	_ = ln.Close()
	return nil
}

func generateRandomString(length int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)

	randomBytes := make([]byte, length)
	_, err := rand.Read(randomBytes)
	if err != nil {
		panic(err)
	}

	for i := 0; i < length; i++ {
		result[i] = chars[randomBytes[i]%byte(len(chars))]
	}

	return string(result)
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
