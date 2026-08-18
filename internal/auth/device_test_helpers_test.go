package auth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
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

func (clock *testDeviceFlowClock) sleep(_ context.Context, duration time.Duration) error {
	clock.sleeps = append(clock.sleeps, duration)
	clock.current = clock.current.Add(duration)
	return nil
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
		discoverEndpoints: func(context.Context, *http.Client, string) (oidcEndpoints, error) {
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
