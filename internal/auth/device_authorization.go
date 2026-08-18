package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

func requestDeviceAuthorization(ctx context.Context, client *http.Client, endpoint string, data url.Values, providerURL string) (DeviceAuthResponse, error) {
	response, err := postOIDCForm(ctx, client, endpoint, data)
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
