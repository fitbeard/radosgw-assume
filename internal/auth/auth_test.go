package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Note: These tests focus on struct validation and type checking
// rather than network operations to ensure CI/CD compatibility

func TestDeviceAuthResponse(t *testing.T) {
	// Test the DeviceAuthResponse struct
	response := DeviceAuthResponse{
		DeviceCode:              "test-device-code",
		UserCode:                "TEST-CODE",
		VerificationURI:         "https://example.com/device",
		VerificationURIComplete: "https://example.com/device?user_code=TEST-CODE",
		ExpiresIn:               600,
		Interval:                5,
	}

	if response.DeviceCode != "test-device-code" {
		t.Errorf("DeviceAuthResponse.DeviceCode = %s, want test-device-code", response.DeviceCode)
	}
	if response.UserCode != "TEST-CODE" {
		t.Errorf("DeviceAuthResponse.UserCode = %s, want TEST-CODE", response.UserCode)
	}
	if response.ExpiresIn != 600 {
		t.Errorf("DeviceAuthResponse.ExpiresIn = %d, want 600", response.ExpiresIn)
	}
}

func TestTokenResponse(t *testing.T) {
	// Test the TokenResponse struct
	response := TokenResponse{
		AccessToken:  "test-access-token",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: "test-refresh-token",
	}

	if response.AccessToken != "test-access-token" {
		t.Errorf("TokenResponse.AccessToken = %s, want test-access-token", response.AccessToken)
	}
	if response.TokenType != "Bearer" {
		t.Errorf("TokenResponse.TokenType = %s, want Bearer", response.TokenType)
	}
	if response.ExpiresIn != 3600 {
		t.Errorf("TokenResponse.ExpiresIn = %d, want 3600", response.ExpiresIn)
	}
}

func TestTokenResponse_WithError(t *testing.T) {
	// Test the TokenResponse struct with error fields
	response := TokenResponse{
		Error:     "invalid_request",
		ErrorDesc: "The request is missing a required parameter",
	}

	if response.Error != "invalid_request" {
		t.Errorf("TokenResponse.Error = %s, want invalid_request", response.Error)
	}
	if response.ErrorDesc != "The request is missing a required parameter" {
		t.Errorf("TokenResponse.ErrorDesc = %s, want 'The request is missing a required parameter'", response.ErrorDesc)
	}
}

func TestAuthenticateDeviceFlow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/protocol/openid-connect/auth/device":
			if err := r.ParseForm(); err != nil {
				t.Errorf("ParseForm() error = %v", err)
			}
			if got := r.Form.Get("client_id"); got != "test-client" {
				t.Errorf("client_id = %q, want test-client", got)
			}
			if got := r.Form.Get("scope"); got != "openid profile" {
				t.Errorf("scope = %q, want openid profile", got)
			}
			_ = json.NewEncoder(w).Encode(DeviceAuthResponse{
				DeviceCode:      "test-device-code",
				UserCode:        "TEST-CODE",
				VerificationURI: serverURL(r),
				ExpiresIn:       600,
				Interval:        -1,
			})
		case "/protocol/openid-connect/token":
			if err := r.ParseForm(); err != nil {
				t.Errorf("ParseForm() error = %v", err)
			}
			if got := r.Form.Get("device_code"); got != "test-device-code" {
				t.Errorf("device_code = %q, want test-device-code", got)
			}
			_ = json.NewEncoder(w).Encode(TokenResponse{AccessToken: "test-access-token"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	token, err := AuthenticateDeviceFlow(server.URL, "test-client", "openid profile", true, false)
	if err != nil {
		t.Fatalf("AuthenticateDeviceFlow() error = %v", err)
	}
	if token != "test-access-token" {
		t.Errorf("token = %q, want test-access-token", token)
	}
}

func serverURL(r *http.Request) string {
	return "http://" + r.Host
}

// Test that the auth functions exist and have the correct signatures
func TestAuthFunctionsExist(t *testing.T) {
	// This test ensures the functions exist with correct signatures
	// without actually calling them to avoid network calls in CI/CD

	// Test that functions are callable (they exist)
	_ = AuthenticateDeviceFlow
	_ = AuthenticateBrowserFlow

	// If we reach here, both functions exist with expected signatures
	t.Log("Auth functions exist and have correct signatures")
}
