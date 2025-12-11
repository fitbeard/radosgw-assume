package auth

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

// AuthenticateDeviceFlow performs OIDC device flow authentication
func AuthenticateDeviceFlow(providerURL, clientID, scope string, sslVerify bool, verboseMode bool) (string, error) {
	tokenEndpoint := fmt.Sprintf("%s/protocol/openid-connect/token", providerURL)
	deviceAuthEndpoint := fmt.Sprintf("%s/protocol/openid-connect/auth/device", providerURL)

	// Step 1: Start device authorization flow
	if verboseMode {
		fmt.Fprintf(os.Stderr, "# Starting device authorization flow...\n")
	}

	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("scope", scope)

	client := &http.Client{}
	if !sslVerify {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	resp, err := client.PostForm(deviceAuthEndpoint, data)
	if err != nil {
		return "", fmt.Errorf("device authorization request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("device authorization failed with status %d: %s", resp.StatusCode, string(body))
	}

	var deviceResponse DeviceAuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&deviceResponse); err != nil {
		return "", fmt.Errorf("failed to parse device authorization response: %w", err)
	}

	if deviceResponse.DeviceCode == "" || deviceResponse.UserCode == "" || deviceResponse.VerificationURI == "" {
		return "", fmt.Errorf("invalid device authorization response: missing required fields")
	}

	// Step 2: Display user instructions
	fmt.Fprintf(os.Stderr, "#\n")
	fmt.Fprintf(os.Stderr, "# 🔐 AUTHENTICATION REQUIRED\n")
	fmt.Fprintf(os.Stderr, "#\n")
	fmt.Fprintf(os.Stderr, "# Please authenticate using your browser:\n")
	fmt.Fprintf(os.Stderr, "#\n")
	fmt.Fprintf(os.Stderr, "# 1. Open this URL: %s\n", deviceResponse.VerificationURI)
	fmt.Fprintf(os.Stderr, "# 2. Enter this code: %s\n", deviceResponse.UserCode)
	if deviceResponse.VerificationURIComplete != "" {
		fmt.Fprintf(os.Stderr, "#\n")
		fmt.Fprintf(os.Stderr, "#    OR use this direct link: %s\n", deviceResponse.VerificationURIComplete)
	}
	fmt.Fprintf(os.Stderr, "#\n")
	fmt.Fprintf(os.Stderr, "# ⏰ You have 60 seconds to complete authentication\n")
	fmt.Fprintf(os.Stderr, "#\n")
	fmt.Fprintf(os.Stderr, "# Waiting for authentication...\n")

	// Step 3: Poll for token
	tokenData := url.Values{}
	tokenData.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	tokenData.Set("client_id", clientID)
	tokenData.Set("device_code", deviceResponse.DeviceCode)

	interval := deviceResponse.Interval
	if interval == 0 {
		interval = 5
	}

	startTime := time.Now()
	timeoutDuration := 60 * time.Second // Use fixed 60-second timeout

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

	for time.Since(startTime) < timeoutDuration {
		time.Sleep(time.Duration(interval) * time.Second)

		resp, err := client.PostForm(tokenEndpoint, tokenData)
		if err != nil {
			progressDone <- true
			return "", fmt.Errorf("token request failed: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()

		var tokenResponse TokenResponse
		if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
			progressDone <- true
			return "", fmt.Errorf("failed to parse token response: %w", err)
		}

		if resp.StatusCode == http.StatusOK && tokenResponse.AccessToken != "" {
			progressDone <- true
			fmt.Fprintf(os.Stderr, "\n") // New line after progress dots
			if verboseMode {
				fmt.Fprintf(os.Stderr, "# ✓ Authentication successful!\n")
			}
			return tokenResponse.AccessToken, nil
		}

		if resp.StatusCode == http.StatusBadRequest {
			switch tokenResponse.Error {
			case "authorization_pending":
				continue
			case "slow_down":
				interval += 5
				continue
			default:
				progressDone <- true
				return "", fmt.Errorf("authentication failed: %s - %s", tokenResponse.Error, tokenResponse.ErrorDesc)
			}
		}
	}

	progressDone <- true
	return "", fmt.Errorf("authentication timeout after %v", timeoutDuration)
}
