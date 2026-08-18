package auth

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestRequestDeviceAuthorizationClosesResponseBody(t *testing.T) {
	body := &trackingReadCloser{Reader: strings.NewReader(validDeviceResponse)}
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       body,
		}, nil
	})}

	response, err := requestDeviceAuthorization(
		t.Context(),
		client,
		"https://oidc.example.com/protocol/openid-connect/auth/device",
		url.Values{"client_id": {"test-client"}},
		"https://oidc.example.com",
	)
	if err != nil {
		t.Fatalf("requestDeviceAuthorization() error = %v", err)
	}
	if response.DeviceCode != testDeviceCode {
		t.Errorf("device code = %q, want %q", response.DeviceCode, testDeviceCode)
	}
	if response.UserCode != testDeviceUserCode {
		t.Errorf("user code = %q, want %q", response.UserCode, testDeviceUserCode)
	}
	if !body.closed {
		t.Error("device authorization response body was not closed")
	}
}
