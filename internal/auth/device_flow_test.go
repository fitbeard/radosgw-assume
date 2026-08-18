package auth

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestAuthenticateDeviceFlowPolling(t *testing.T) {
	client := newDeviceFlowHTTPClient(
		testDeviceHTTPResponse{status: http.StatusOK, body: validDeviceResponse},
		testDeviceHTTPResponse{status: http.StatusBadRequest, body: `{"error":"authorization_pending"}`},
		testDeviceHTTPResponse{status: http.StatusBadRequest, body: `{"error":"slow_down"}`},
		testDeviceHTTPResponse{status: http.StatusOK, body: `{"access_token":"test-access-token"}`},
	)
	var stderr bytes.Buffer
	dependencies, clock, progress := newTestDeviceFlowDependencies(&stderr, client)
	options := testOIDCOptions()
	options.Scope = "openid profile"
	options.Verbose = true

	token, err := authenticateDeviceFlow(t.Context(), options, dependencies)
	if err != nil {
		t.Fatalf("authenticateDeviceFlow() error = %v", err)
	}
	if token != "test-access-token" {
		t.Errorf("token = %q, want test-access-token", token)
	}

	wantSleeps := []time.Duration{2 * time.Second, 2 * time.Second, 7 * time.Second}
	if len(clock.sleeps) != len(wantSleeps) {
		t.Fatalf("polling sleeps = %v, want %v", clock.sleeps, wantSleeps)
	}
	for index, want := range wantSleeps {
		if clock.sleeps[index] != want {
			t.Errorf("polling sleep %d = %v, want %v", index, clock.sleeps[index], want)
		}
	}
	if !progress.stopped || progress.stoppedQuiet {
		t.Errorf("progress state = %+v, want normal stop", progress)
	}

	for _, want := range []string{
		"# Starting device authorization flow...",
		"# 1. Open this URL: https://oidc.example.com/device",
		"# 2. Enter this code: TEST-CODE",
		"#    OR use this direct link: https://oidc.example.com/device?user_code=TEST-CODE",
		"# ⏰ You have 600 seconds (10m) to complete authentication",
		"# ✓ Authentication successful!",
	} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr does not contain %q:\n%s", want, stderr.String())
		}
	}
}

func TestAuthenticateDeviceFlowUsesDefaultPollingInterval(t *testing.T) {
	client := newDeviceFlowHTTPClient(
		testDeviceHTTPResponse{
			status: http.StatusOK,
			body:   `{"device_code":"test-device-code","user_code":"TEST-CODE","verification_uri":"https://oidc.example.com/device","expires_in":600}`,
		},
		testDeviceHTTPResponse{status: http.StatusOK, body: `{"access_token":"test-access-token"}`},
	)
	dependencies, clock, _ := newTestDeviceFlowDependencies(io.Discard, client)

	_, err := authenticateDeviceFlow(t.Context(), testOIDCOptions(), dependencies)
	if err != nil {
		t.Fatalf("authenticateDeviceFlow() error = %v", err)
	}
	if len(clock.sleeps) != 1 || clock.sleeps[0] != DefaultPollingInterval*time.Second {
		t.Errorf("polling sleeps = %v, want [%v]", clock.sleeps, DefaultPollingInterval*time.Second)
	}
}

func TestAuthenticateDeviceFlowErrors(t *testing.T) {
	tests := []struct {
		name          string
		responses     []testDeviceHTTPResponse
		configure     func(*deviceFlowDependencies, *testDeviceFlowClock)
		wantContain   string
		wantQuietStop bool
	}{
		{
			name: "PKCE generation",
			configure: func(dependencies *deviceFlowDependencies, _ *testDeviceFlowClock) {
				dependencies.generatePKCE = func(string) (string, string, string, error) {
					return "", "", "", errors.New("PKCE failed")
				}
			},
			wantContain: "PKCE failed",
		},
		{
			name: "OIDC discovery",
			configure: func(dependencies *deviceFlowDependencies, _ *testDeviceFlowClock) {
				dependencies.discoverEndpoints = func(context.Context, *http.Client, string) (oidcEndpoints, error) {
					return oidcEndpoints{}, errors.New("discovery failed")
				}
			},
			wantContain: "discovery failed",
		},
		{
			name: "missing device endpoint",
			configure: func(dependencies *deviceFlowDependencies, _ *testDeviceFlowClock) {
				dependencies.discoverEndpoints = func(context.Context, *http.Client, string) (oidcEndpoints, error) {
					return oidcEndpoints{token: "https://oidc.example.com/token"}, nil
				}
			},
			wantContain: "device_authorization_endpoint",
		},
		{
			name:        "authorization transport",
			responses:   []testDeviceHTTPResponse{{err: errors.New("connection failed")}},
			wantContain: "device authorization request failed",
		},
		{
			name: "authorization status",
			responses: []testDeviceHTTPResponse{{
				status: http.StatusBadRequest,
				body:   `{"error":"invalid_request","error_description":"missing challenge"}`,
			}},
			wantContain: "invalid request: the authentication request was malformed. missing challenge",
		},
		{
			name: "oversized authorization response",
			responses: []testDeviceHTTPResponse{{
				status: http.StatusBadRequest,
				body:   strings.Repeat("x", maxOIDCResponseBodySize+1),
			}},
			wantContain: "OIDC response body exceeds 65536-byte limit",
		},
		{
			name: "malformed authorization response",
			responses: []testDeviceHTTPResponse{{
				status: http.StatusOK,
				body:   `{`,
			}},
			wantContain: "failed to parse device authorization response",
		},
		{
			name: "incomplete authorization response",
			responses: []testDeviceHTTPResponse{{
				status: http.StatusOK,
				body:   `{"device_code":"test-device-code"}`,
			}},
			wantContain: "invalid device authorization response",
		},
		{
			name: "missing authorization expiry",
			responses: []testDeviceHTTPResponse{{
				status: http.StatusOK,
				body:   `{"device_code":"test-device-code","user_code":"TEST-CODE","verification_uri":"https://oidc.example.com/device"}`,
			}},
			wantContain: "expires_in must be a positive number of seconds",
		},
		{
			name: "negative authorization expiry",
			responses: []testDeviceHTTPResponse{{
				status: http.StatusOK,
				body:   `{"device_code":"test-device-code","user_code":"TEST-CODE","verification_uri":"https://oidc.example.com/device","expires_in":-1}`,
			}},
			wantContain: "expires_in must be a positive number of seconds",
		},
		{
			name: "negative polling interval",
			responses: []testDeviceHTTPResponse{{
				status: http.StatusOK,
				body:   `{"device_code":"test-device-code","user_code":"TEST-CODE","verification_uri":"https://oidc.example.com/device","expires_in":600,"interval":-1}`,
			}},
			wantContain: "interval must not be negative",
		},
		{
			name: "token transport",
			responses: []testDeviceHTTPResponse{
				{status: http.StatusOK, body: validDeviceResponse},
				{err: errors.New("connection failed")},
			},
			wantContain:   "token request failed",
			wantQuietStop: true,
		},
		{
			name: "malformed token response",
			responses: []testDeviceHTTPResponse{
				{status: http.StatusOK, body: validDeviceResponse},
				{status: http.StatusOK, body: `{`},
			},
			wantContain:   "failed to parse token response",
			wantQuietStop: true,
		},
		{
			name: "provider token error",
			responses: []testDeviceHTTPResponse{
				{status: http.StatusOK, body: validDeviceResponse},
				{status: http.StatusBadRequest, body: `{"error":"access_denied","error_description":"cancelled"}`},
			},
			wantContain:   "access denied",
			wantQuietStop: true,
		},
		{
			name: "unexpected token status with OIDC error",
			responses: []testDeviceHTTPResponse{
				{status: http.StatusOK, body: validDeviceResponse},
				{status: http.StatusServiceUnavailable, body: `{"error":"temporarily_unavailable"}`},
			},
			wantContain:   "temporarily unavailable",
			wantQuietStop: true,
		},
		{
			name: "unexpected token status with plain response",
			responses: []testDeviceHTTPResponse{
				{status: http.StatusOK, body: validDeviceResponse},
				{status: http.StatusBadGateway, body: "upstream unavailable"},
			},
			wantContain:   "token request failed with status 502: upstream unavailable",
			wantQuietStop: true,
		},
		{
			name: "missing access token",
			responses: []testDeviceHTTPResponse{
				{status: http.StatusOK, body: validDeviceResponse},
				{status: http.StatusOK, body: `{}`},
			},
			wantContain:   "no access token received",
			wantQuietStop: true,
		},
		{
			name: "oversized token response",
			responses: []testDeviceHTTPResponse{
				{status: http.StatusOK, body: validDeviceResponse},
				{status: http.StatusOK, body: strings.Repeat("x", maxOIDCResponseBodySize+1)},
			},
			wantContain:   "OIDC response body exceeds 65536-byte limit",
			wantQuietStop: true,
		},
		{
			name: "provider expiry",
			responses: []testDeviceHTTPResponse{
				{
					status: http.StatusOK,
					body:   `{"device_code":"test-device-code","user_code":"TEST-CODE","verification_uri":"https://oidc.example.com/device","expires_in":3,"interval":2}`,
				},
				{status: http.StatusBadRequest, body: `{"error":"authorization_pending"}`},
			},
			wantContain:   "device authorization expired after 3s",
			wantQuietStop: true,
		},
		{
			name: "slow down bounded by provider expiry",
			responses: []testDeviceHTTPResponse{
				{
					status: http.StatusOK,
					body:   `{"device_code":"test-device-code","user_code":"TEST-CODE","verification_uri":"https://oidc.example.com/device","expires_in":8,"interval":4}`,
				},
				{status: http.StatusBadRequest, body: `{"error":"slow_down"}`},
			},
			wantContain:   "device authorization expired after 8s",
			wantQuietStop: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			responses := test.responses
			if len(responses) == 0 {
				responses = []testDeviceHTTPResponse{
					{status: http.StatusOK, body: validDeviceResponse},
					{status: http.StatusOK, body: `{"access_token":"test-access-token"}`},
				}
			}
			dependencies, clock, progress := newTestDeviceFlowDependencies(
				io.Discard,
				newDeviceFlowHTTPClient(responses...),
			)
			if test.configure != nil {
				test.configure(&dependencies, clock)
			}

			_, err := authenticateDeviceFlow(t.Context(), testOIDCOptions(), dependencies)
			if err == nil || !strings.Contains(err.Error(), test.wantContain) {
				t.Errorf("authenticateDeviceFlow() error = %v, want containing %q", err, test.wantContain)
			}
			if progress.stoppedQuiet != test.wantQuietStop {
				t.Errorf("progress stopped quietly = %v, want %v", progress.stoppedQuiet, test.wantQuietStop)
			}
		})
	}
}

func TestAuthenticateDeviceFlowCancelsPollingWait(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	dependencies, _, progress := newTestDeviceFlowDependencies(
		io.Discard,
		newDeviceFlowHTTPClient(testDeviceHTTPResponse{status: http.StatusOK, body: validDeviceResponse}),
	)
	dependencies.sleep = func(ctx context.Context, _ time.Duration) error {
		cancel()
		return sleepWithContext(ctx, time.Hour)
	}

	_, err := authenticateDeviceFlow(ctx, testOIDCOptions(), dependencies)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("authenticateDeviceFlow() error = %v, want context cancellation", err)
	}
	if !progress.stoppedQuiet {
		t.Error("authentication progress was not stopped quietly after cancellation")
	}
}
