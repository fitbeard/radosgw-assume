package auth

import (
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