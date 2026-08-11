package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

type deviceFlowProgress interface {
	Stop()
	StopQuiet()
}

type deviceFlowDependencies struct {
	stderr io.Writer

	generatePKCE  func(string) (string, string, string, error)
	newHTTPClient func(bool) *http.Client
	now           func() time.Time
	sleep         func(time.Duration)
	newProgress   func() deviceFlowProgress
}

func newDeviceFlowDependencies() deviceFlowDependencies {
	return deviceFlowDependencies{
		stderr:        os.Stderr,
		generatePKCE:  GeneratePKCE,
		newHTTPClient: NewHTTPClient,
		now:           time.Now,
		sleep:         time.Sleep,
		newProgress:   func() deviceFlowProgress { return NewProgressIndicator() },
	}
}

// AuthenticateDeviceFlow performs OIDC device flow authentication with PKCE.
func AuthenticateDeviceFlow(providerURL, clientID, scope, pkceMethod string, sslVerify bool, verboseMode bool) (string, error) {
	return authenticateDeviceFlow(
		providerURL,
		clientID,
		scope,
		pkceMethod,
		sslVerify,
		verboseMode,
		newDeviceFlowDependencies(),
	)
}

func authenticateDeviceFlow(providerURL, clientID, scope, pkceMethod string, sslVerify bool, verboseMode bool, dependencies deviceFlowDependencies) (string, error) {
	tokenEndpoint := fmt.Sprintf("%s/protocol/openid-connect/token", providerURL)
	deviceAuthEndpoint := fmt.Sprintf("%s/protocol/openid-connect/auth/device", providerURL)
	codeVerifier, codeChallenge, resolvedPKCEMethod, err := dependencies.generatePKCE(pkceMethod)
	if err != nil {
		return "", err
	}

	// Step 1: Start device authorization flow
	if verboseMode {
		_, _ = fmt.Fprintln(dependencies.stderr, "# Starting device authorization flow...")
	}

	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("scope", scope)
	data.Set("code_challenge", codeChallenge)
	data.Set("code_challenge_method", resolvedPKCEMethod)

	client := dependencies.newHTTPClient(sslVerify)
	deviceResponse, err := requestDeviceAuthorization(client, deviceAuthEndpoint, data)
	if err != nil {
		return "", err
	}

	// Step 2: Display user instructions
	printDeviceAuthenticationInstructions(dependencies.stderr, deviceResponse)

	// Step 3: Poll for token
	tokenData := url.Values{}
	tokenData.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	tokenData.Set("client_id", clientID)
	tokenData.Set("device_code", deviceResponse.DeviceCode)
	tokenData.Set("code_verifier", codeVerifier)

	interval := deviceResponse.Interval
	if interval == 0 {
		interval = DefaultPollingInterval
	}

	startTime := dependencies.now()

	// Progress indication
	progress := dependencies.newProgress()

	for dependencies.now().Sub(startTime) < AuthTimeout {
		dependencies.sleep(time.Duration(interval) * time.Second)

		response, err := client.PostForm(tokenEndpoint, tokenData)
		if err != nil {
			progress.StopQuiet()
			return "", fmt.Errorf("token request failed: %w", err)
		}
		tokenResponse, err := decodeTokenResponseAndClose(response)
		if err != nil {
			progress.StopQuiet()
			return "", fmt.Errorf("failed to parse token response: %w", err)
		}

		if response.StatusCode == http.StatusOK && tokenResponse.AccessToken != "" {
			progress.Stop()
			if verboseMode {
				_, _ = fmt.Fprintln(dependencies.stderr, "# ✓ Authentication successful!")
			}
			return tokenResponse.AccessToken, nil
		}

		if response.StatusCode == http.StatusBadRequest {
			switch tokenResponse.Error {
			case "authorization_pending":
				continue
			case "slow_down":
				interval += DefaultPollingInterval
				continue
			default:
				progress.StopQuiet()
				return "", FormatOIDCError(tokenResponse.Error, tokenResponse.ErrorDesc, providerURL)
			}
		}
	}

	progress.StopQuiet()
	return "", fmt.Errorf("authentication timeout after %v", AuthTimeout)
}

func requestDeviceAuthorization(client *http.Client, endpoint string, data url.Values) (DeviceAuthResponse, error) {
	response, err := client.PostForm(endpoint, data)
	if err != nil {
		return DeviceAuthResponse{}, fmt.Errorf("device authorization request failed: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		return DeviceAuthResponse{}, fmt.Errorf("device authorization failed with status %d: %s", response.StatusCode, string(body))
	}

	var deviceResponse DeviceAuthResponse
	if err := json.NewDecoder(response.Body).Decode(&deviceResponse); err != nil {
		return DeviceAuthResponse{}, fmt.Errorf("failed to parse device authorization response: %w", err)
	}

	if deviceResponse.DeviceCode == "" || deviceResponse.UserCode == "" || deviceResponse.VerificationURI == "" {
		return DeviceAuthResponse{}, fmt.Errorf("invalid device authorization response: missing required fields")
	}

	return deviceResponse, nil
}

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
	_, _ = fmt.Fprintln(stderr, "# ⏰ You have 60 seconds to complete authentication")
	_, _ = fmt.Fprintln(stderr, "#")
	_, _ = fmt.Fprintln(stderr, "# Waiting for authentication...")
}

// decodeTokenResponseAndClose decodes a polling response and always closes its
// body before returning so the polling loop never accumulates open responses.
func decodeTokenResponseAndClose(resp *http.Response) (TokenResponse, error) {
	defer func() { _ = resp.Body.Close() }()

	var tokenResponse TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return TokenResponse{}, err
	}

	return tokenResponse, nil
}
