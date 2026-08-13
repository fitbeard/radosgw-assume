package auth

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

const (
	testDeviceCode         = "test-device-code"
	testDeviceUserCode     = "TEST-CODE"
	testDeviceCodeVerifier = "test-device-verifier"
	validDeviceResponse    = `{"device_code":"test-device-code","user_code":"TEST-CODE","verification_uri":"https://oidc.example.com/device","verification_uri_complete":"https://oidc.example.com/device?user_code=TEST-CODE","expires_in":600,"interval":2}`
)

type testDeviceFlowClock struct {
	current time.Time
	sleeps  []time.Duration
}

func (clock *testDeviceFlowClock) now() time.Time {
	return clock.current
}

func (clock *testDeviceFlowClock) sleep(duration time.Duration) {
	clock.sleeps = append(clock.sleeps, duration)
	clock.current = clock.current.Add(duration)
}

type testDeviceFlowProgress struct {
	stopped      bool
	stoppedQuiet bool
}

func (progress *testDeviceFlowProgress) Stop() {
	progress.stopped = true
}

func (progress *testDeviceFlowProgress) StopQuiet() {
	progress.stoppedQuiet = true
}

type testDeviceHTTPResponse struct {
	status int
	body   string
	err    error
}

func TestAuthenticateDeviceFlowPolling(t *testing.T) {
	client := newDeviceFlowHTTPClient(
		testDeviceHTTPResponse{status: http.StatusOK, body: validDeviceResponse},
		testDeviceHTTPResponse{status: http.StatusBadRequest, body: `{"error":"authorization_pending"}`},
		testDeviceHTTPResponse{status: http.StatusBadRequest, body: `{"error":"slow_down"}`},
		testDeviceHTTPResponse{status: http.StatusOK, body: `{"access_token":"test-access-token"}`},
	)
	var stderr bytes.Buffer
	dependencies, clock, progress := newTestDeviceFlowDependencies(&stderr, client)

	token, err := authenticateDeviceFlow(
		"https://oidc.example.com",
		"test-client",
		"openid profile",
		PKCEMethodS256,
		true,
		true,
		dependencies,
	)
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
			body:   `{"device_code":"test-device-code","user_code":"TEST-CODE","verification_uri":"https://oidc.example.com/device"}`,
		},
		testDeviceHTTPResponse{status: http.StatusOK, body: `{"access_token":"test-access-token"}`},
	)
	dependencies, clock, _ := newTestDeviceFlowDependencies(io.Discard, client)

	_, err := authenticateDeviceFlow(
		"https://oidc.example.com",
		"test-client",
		"openid",
		PKCEMethodS256,
		true,
		false,
		dependencies,
	)
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
				dependencies.discoverEndpoints = func(*http.Client, string) (oidcEndpoints, error) {
					return oidcEndpoints{}, errors.New("discovery failed")
				}
			},
			wantContain: "discovery failed",
		},
		{
			name: "missing device endpoint",
			configure: func(dependencies *deviceFlowDependencies, _ *testDeviceFlowClock) {
				dependencies.discoverEndpoints = func(*http.Client, string) (oidcEndpoints, error) {
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
			name: "timeout",
			responses: []testDeviceHTTPResponse{
				{status: http.StatusOK, body: validDeviceResponse},
				{status: http.StatusBadRequest, body: `{"error":"authorization_pending"}`},
			},
			configure: func(dependencies *deviceFlowDependencies, clock *testDeviceFlowClock) {
				dependencies.sleep = func(duration time.Duration) {
					clock.sleeps = append(clock.sleeps, duration)
					clock.current = clock.current.Add(AuthTimeout)
				}
			},
			wantContain:   "authentication timeout",
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

			_, err := authenticateDeviceFlow(
				"https://oidc.example.com",
				"test-client",
				"openid",
				PKCEMethodS256,
				true,
				false,
				dependencies,
			)
			if err == nil || !strings.Contains(err.Error(), test.wantContain) {
				t.Errorf("authenticateDeviceFlow() error = %v, want containing %q", err, test.wantContain)
			}
			if progress.stoppedQuiet != test.wantQuietStop {
				t.Errorf("progress stopped quietly = %v, want %v", progress.stoppedQuiet, test.wantQuietStop)
			}
		})
	}
}

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

func newTestDeviceFlowDependencies(stderr io.Writer, client *http.Client) (deviceFlowDependencies, *testDeviceFlowClock, *testDeviceFlowProgress) {
	clock := &testDeviceFlowClock{current: time.Unix(0, 0)}
	progress := &testDeviceFlowProgress{}
	return deviceFlowDependencies{
		stderr: stderr,
		generatePKCE: func(method string) (string, string, string, error) {
			if method == "" {
				method = DefaultPKCEMethod
			}
			challenge := "test-device-challenge"
			if method == PKCEMethodPlain {
				challenge = testDeviceCodeVerifier
			}
			return testDeviceCodeVerifier, challenge, method, nil
		},
		newHTTPClient: func(bool) *http.Client { return client },
		discoverEndpoints: func(*http.Client, string) (oidcEndpoints, error) {
			return oidcEndpoints{
				deviceAuthorization: "https://oidc.example.com/device",
				token:               "https://oidc.example.com/token",
			}, nil
		},
		now:         clock.now,
		sleep:       clock.sleep,
		newProgress: func() deviceFlowProgress { return progress },
	}, clock, progress
}

func newDeviceFlowHTTPClient(responses ...testDeviceHTTPResponse) *http.Client {
	responseIndex := 0
	return &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if responseIndex >= len(responses) {
			return nil, errors.New("unexpected device flow request")
		}
		response := responses[responseIndex]
		responseIndex++
		if response.err != nil {
			return nil, response.err
		}
		return &http.Response{
			StatusCode: response.status,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(response.body)),
			Request:    request,
		}, nil
	})}
}
