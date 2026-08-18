package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/fitbeard/radosgw-assume/pkg/duration"
)

type deviceFlowProgress interface {
	Stop()
	StopQuiet()
}

type deviceFlowDependencies struct {
	stderr io.Writer

	generatePKCE      func(string) (string, string, string, error)
	newHTTPClient     func(bool) *http.Client
	discoverEndpoints func(*http.Client, string) (oidcEndpoints, error)
	now               func() time.Time
	sleep             func(time.Duration)
	newProgress       func() deviceFlowProgress
}

func newDeviceFlowDependencies() deviceFlowDependencies {
	return deviceFlowDependencies{
		stderr:            os.Stderr,
		generatePKCE:      GeneratePKCE,
		newHTTPClient:     NewHTTPClient,
		discoverEndpoints: discoverOIDCEndpoints,
		now:               time.Now,
		sleep:             time.Sleep,
		newProgress:       func() deviceFlowProgress { return NewProgressIndicator() },
	}
}

// AuthenticateDeviceFlow performs OIDC device flow authentication with PKCE.
func AuthenticateDeviceFlow(providerURL, clientID, scope, pkceMethod string, sslVerify bool, verboseMode bool) (string, error) {
	return AuthenticateDeviceFlowWithOutput(providerURL, clientID, scope, pkceMethod, sslVerify, verboseMode, os.Stderr)
}

// AuthenticateDeviceFlowWithOutput performs OIDC device flow authentication
// and writes user interaction to output.
func AuthenticateDeviceFlowWithOutput(providerURL, clientID, scope, pkceMethod string, sslVerify bool, verboseMode bool, output io.Writer) (string, error) {
	dependencies := newDeviceFlowDependencies()
	dependencies.stderr = output
	dependencies.newProgress = func() deviceFlowProgress { return newProgressIndicatorWithOutput(output) }
	return authenticateDeviceFlow(
		providerURL,
		clientID,
		scope,
		pkceMethod,
		sslVerify,
		verboseMode,
		dependencies,
	)
}

func authenticateDeviceFlow(providerURL, clientID, scope, pkceMethod string, sslVerify bool, verboseMode bool, dependencies deviceFlowDependencies) (string, error) {
	codeVerifier, codeChallenge, resolvedPKCEMethod, err := dependencies.generatePKCE(pkceMethod)
	if err != nil {
		return "", err
	}
	client := dependencies.newHTTPClient(sslVerify)
	endpoints, err := dependencies.discoverEndpoints(client, providerURL)
	if err != nil {
		return "", err
	}
	if err := endpoints.validateDeviceFlow(); err != nil {
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

	deviceResponse, err := requestDeviceAuthorization(client, endpoints.deviceAuthorization, data, providerURL)
	if err != nil {
		return "", err
	}
	deviceLifetime := time.Duration(deviceResponse.ExpiresIn) * time.Second
	expiresAt := dependencies.now().Add(deviceLifetime)

	// Step 2: Display user instructions
	printDeviceAuthenticationInstructions(dependencies.stderr, deviceResponse)

	// Step 3: Poll for token
	tokenData := url.Values{}
	tokenData.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	tokenData.Set("client_id", clientID)
	tokenData.Set("device_code", deviceResponse.DeviceCode)
	tokenData.Set("code_verifier", codeVerifier)

	pollInterval := time.Duration(deviceResponse.Interval) * time.Second
	if pollInterval == 0 {
		pollInterval = DefaultPollingInterval * time.Second
	}
	pollInterval = min(pollInterval, deviceLifetime)

	// Progress indication
	progress := dependencies.newProgress()

	for {
		remaining := expiresAt.Sub(dependencies.now())
		if remaining <= 0 {
			break
		}
		wait := min(pollInterval, remaining)
		dependencies.sleep(wait)
		if !dependencies.now().Before(expiresAt) {
			break
		}

		response, err := client.PostForm(endpoints.token, tokenData)
		if err != nil {
			progress.StopQuiet()
			return "", fmt.Errorf("token request failed: %w", err)
		}
		body, err := readOIDCResponseAndClose(response)
		if err != nil {
			progress.StopQuiet()
			return "", fmt.Errorf("failed to read token response: %w", err)
		}

		tokenResponse, err := decodeOIDCTokenResponse("token request", response.StatusCode, body, providerURL)
		if err != nil {
			progress.StopQuiet()
			return "", err
		}

		switch response.StatusCode {
		case http.StatusOK:
			accessToken, err := accessTokenFromOIDCResponse(tokenResponse, providerURL)
			if err != nil {
				progress.StopQuiet()
				return "", err
			}

			progress.Stop()
			if verboseMode {
				_, _ = fmt.Fprintln(dependencies.stderr, "# ✓ Authentication successful!")
			}
			return accessToken, nil
		case http.StatusBadRequest:
			switch tokenResponse.Error {
			case "authorization_pending":
				continue
			case "slow_down":
				slowDown := DefaultPollingInterval * time.Second
				if deviceLifetime-pollInterval < slowDown {
					pollInterval = deviceLifetime
				} else {
					pollInterval += slowDown
				}
				continue
			default:
				progress.StopQuiet()
				return "", oidcHTTPStatusError("token request", response.StatusCode, body, providerURL)
			}
		default:
			progress.StopQuiet()
			return "", oidcHTTPStatusError("token request", response.StatusCode, body, providerURL)
		}
	}

	progress.StopQuiet()
	return "", fmt.Errorf("device authorization expired after %s; start authentication again", duration.Format(deviceLifetime))
}

func requestDeviceAuthorization(client *http.Client, endpoint string, data url.Values, providerURL string) (DeviceAuthResponse, error) {
	response, err := client.PostForm(endpoint, data)
	if err != nil {
		return DeviceAuthResponse{}, fmt.Errorf("device authorization request failed: %w", err)
	}
	body, err := readOIDCResponseAndClose(response)
	if err != nil {
		return DeviceAuthResponse{}, fmt.Errorf("failed to read device authorization response: %w", err)
	}

	if response.StatusCode != http.StatusOK {
		return DeviceAuthResponse{}, oidcHTTPStatusError("device authorization", response.StatusCode, body, providerURL)
	}

	var deviceResponse DeviceAuthResponse
	if err := json.Unmarshal(body, &deviceResponse); err != nil {
		return DeviceAuthResponse{}, fmt.Errorf("failed to parse device authorization response: %w", err)
	}

	if deviceResponse.DeviceCode == "" || deviceResponse.UserCode == "" || deviceResponse.VerificationURI == "" {
		return DeviceAuthResponse{}, fmt.Errorf("invalid device authorization response: missing required fields")
	}
	if _, err := deviceResponseDuration("expires_in", deviceResponse.ExpiresIn); err != nil {
		return DeviceAuthResponse{}, err
	}
	if deviceResponse.Interval < 0 {
		return DeviceAuthResponse{}, fmt.Errorf("invalid device authorization response: interval must not be negative")
	}
	if deviceResponse.Interval > 0 {
		if _, err := deviceResponseDuration("interval", deviceResponse.Interval); err != nil {
			return DeviceAuthResponse{}, err
		}
	}

	return deviceResponse, nil
}

func deviceResponseDuration(field string, seconds int) (time.Duration, error) {
	if seconds <= 0 {
		return 0, fmt.Errorf("invalid device authorization response: %s must be a positive number of seconds", field)
	}
	value := time.Duration(seconds)
	result := value * time.Second
	if result <= 0 || result/time.Second != value {
		return 0, fmt.Errorf("invalid device authorization response: %s is too large", field)
	}
	return result, nil
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
	lifetime := time.Duration(response.ExpiresIn) * time.Second
	_, _ = fmt.Fprintf(stderr, "# ⏰ You have %d seconds (%s) to complete authentication\n", response.ExpiresIn, duration.Format(lifetime))
	_, _ = fmt.Fprintln(stderr, "#")
	_, _ = fmt.Fprintln(stderr, "# Waiting for authentication...")
}
