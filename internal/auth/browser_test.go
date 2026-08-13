package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const (
	testBrowserState         = "test-state"
	testBrowserCode          = "test-code"
	testBrowserCodeVerifier  = "test-verifier"
	testBrowserCodeChallenge = "test-challenge"
)

type testBrowserFlowTimer struct {
	done    chan time.Time
	stopped bool
}

func (timer *testBrowserFlowTimer) Done() <-chan time.Time {
	return timer.done
}

func (timer *testBrowserFlowTimer) Stop() {
	timer.stopped = true
}

type testBrowserFlowProgress struct {
	stopped      bool
	stoppedQuiet bool
}

func (progress *testBrowserFlowProgress) Stop() {
	progress.stopped = true
}

func (progress *testBrowserFlowProgress) StopQuiet() {
	progress.stoppedQuiet = true
}

func TestAuthenticateBrowserFlow(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/.well-known/openid-configuration":
			writer.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(writer, `{
				"issuer":%q,
				"authorization_endpoint":%q,
				"token_endpoint":%q
			}`, serverURL(request), serverURL(request)+"/oauth2/default/v1/authorize?audience=storage", serverURL(request)+"/oauth2/default/v1/token")
			return
		case "/oauth2/default/v1/token":
		default:
			http.NotFound(writer, request)
			return
		}
		if err := request.ParseForm(); err != nil {
			t.Errorf("ParseForm() error = %v", err)
			return
		}

		wantForm := map[string]string{
			"grant_type":    "authorization_code",
			"client_id":     "test-client",
			"code":          testBrowserCode,
			"code_verifier": testBrowserCodeVerifier,
		}
		for key, want := range wantForm {
			if got := request.Form.Get(key); got != want {
				t.Errorf("token request %s = %q, want %q", key, got, want)
			}
		}
		if redirectURI := request.Form.Get("redirect_uri"); !strings.HasPrefix(redirectURI, "http://localhost:") || !strings.HasSuffix(redirectURI, "/callback") {
			t.Errorf("token request redirect_uri = %q, want loopback callback", redirectURI)
		}

		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"access_token":"test-access-token"}`)
	}))
	t.Cleanup(tokenServer.Close)

	var stderr bytes.Buffer
	dependencies := newTestBrowserFlowDependencies(&stderr)
	dependencies.startCallbackServer = func(results chan<- browserCallbackResult) (*browserCallbackServer, error) {
		return startBrowserCallbackServer(callbackListenHost, []int{0}, results)
	}
	dependencies.openBrowser = func(authURL string) error {
		parsedAuthURL, err := url.Parse(authURL)
		if err != nil {
			return fmt.Errorf("parse authorization URL: %w", err)
		}
		if parsedAuthURL.Path != "/oauth2/default/v1/authorize" {
			return fmt.Errorf("authorization path = %q", parsedAuthURL.Path)
		}

		query := parsedAuthURL.Query()
		wantQuery := map[string]string{
			"audience":              "storage",
			"client_id":             "test-client",
			"response_type":         "code",
			"scope":                 "openid profile",
			"state":                 testBrowserState,
			"code_challenge":        testBrowserCodeChallenge,
			"code_challenge_method": PKCEMethodS256,
		}
		for key, want := range wantQuery {
			if got := query.Get(key); got != want {
				return fmt.Errorf("authorization query %s = %q, want %q", key, got, want)
			}
		}

		callbackURL, err := url.Parse(query.Get("redirect_uri"))
		if err != nil {
			return fmt.Errorf("parse redirect URI: %w", err)
		}
		callbackQuery := callbackURL.Query()
		callbackQuery.Set("code", testBrowserCode)
		callbackQuery.Set("state", testBrowserState)
		callbackURL.RawQuery = callbackQuery.Encode()

		response, err := http.Get(callbackURL.String()) //nolint:gosec // Test exercises the loopback callback server.
		if err != nil {
			return fmt.Errorf("invoke callback: %w", err)
		}
		defer func() { _ = response.Body.Close() }()
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("callback status = %d", response.StatusCode)
		}
		return nil
	}
	dependencies.newHTTPClient = func(sslVerify bool) *http.Client {
		if !sslVerify {
			t.Error("sslVerify = false, want true")
		}
		return tokenServer.Client()
	}
	dependencies.discoverEndpoints = discoverOIDCEndpoints

	token, err := authenticateBrowserFlow(
		tokenServer.URL+"/",
		"test-client",
		"openid profile",
		PKCEMethodS256,
		true,
		true,
		dependencies,
	)
	if err != nil {
		t.Fatalf("authenticateBrowserFlow() error = %v", err)
	}
	if token != "test-access-token" {
		t.Errorf("token = %q, want test-access-token", token)
	}

	for _, want := range []string{
		"# ✓ Browser opened successfully",
		"# ✓ Authentication successful!",
		"# ✓ Successfully obtained access token",
	} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr does not contain %q:\n%s", want, stderr.String())
		}
	}
}

func TestAuthenticateBrowserFlowBrowserFallback(t *testing.T) {
	var stderr bytes.Buffer
	dependencies := newTestBrowserFlowDependencies(&stderr)
	dependencies.startCallbackServer = func(results chan<- browserCallbackResult) (*browserCallbackServer, error) {
		results <- browserCallbackResult{code: testBrowserCode, state: testBrowserState}
		return newTestBrowserCallbackServer(CallbackFallbackPort), nil
	}
	dependencies.openBrowser = func(string) error { return errors.New("browser unavailable") }

	token, err := authenticateBrowserFlow(
		"https://oidc.example.com",
		"test-client",
		"openid",
		PKCEMethodPlain,
		true,
		true,
		dependencies,
	)
	if err != nil {
		t.Fatalf("authenticateBrowserFlow() error = %v", err)
	}
	if token != "test-access-token" {
		t.Errorf("token = %q, want test-access-token", token)
	}

	for _, want := range []string{
		fmt.Sprintf("using fallback port %d", CallbackFallbackPort),
		"Could not open browser automatically: browser unavailable",
		"Please manually open this URL",
	} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr does not contain %q:\n%s", want, stderr.String())
		}
	}
}

func TestAuthenticateBrowserFlowErrors(t *testing.T) {
	tests := []struct {
		name        string
		configure   func(*browserFlowDependencies)
		wantContain string
	}{
		{
			name: "state generation",
			configure: func(dependencies *browserFlowDependencies) {
				dependencies.generateRandomString = func(int) (string, error) {
					return "", errors.New("random source failed")
				}
			},
			wantContain: "failed to generate state: random source failed",
		},
		{
			name: "PKCE generation",
			configure: func(dependencies *browserFlowDependencies) {
				dependencies.generatePKCE = func(string) (string, string, string, error) {
					return "", "", "", errors.New("invalid PKCE method")
				}
			},
			wantContain: "invalid PKCE method",
		},
		{
			name: "OIDC discovery",
			configure: func(dependencies *browserFlowDependencies) {
				dependencies.discoverEndpoints = func(*http.Client, string) (oidcEndpoints, error) {
					return oidcEndpoints{}, errors.New("discovery failed")
				}
			},
			wantContain: "discovery failed",
		},
		{
			name: "missing browser endpoint",
			configure: func(dependencies *browserFlowDependencies) {
				dependencies.discoverEndpoints = func(*http.Client, string) (oidcEndpoints, error) {
					return oidcEndpoints{token: "https://oidc.example.com/token"}, nil
				}
			},
			wantContain: "authorization_endpoint",
		},
		{
			name: "callback server startup",
			configure: func(dependencies *browserFlowDependencies) {
				dependencies.startCallbackServer = func(chan<- browserCallbackResult) (*browserCallbackServer, error) {
					return nil, errors.New("listen failed")
				}
			},
			wantContain: "both callback ports",
		},
		{
			name: "callback server runtime",
			configure: func(dependencies *browserFlowDependencies) {
				dependencies.startCallbackServer = func(chan<- browserCallbackResult) (*browserCallbackServer, error) {
					server := newTestBrowserCallbackServer(CallbackPort)
					serverErrors := make(chan error, 1)
					serverErrors <- errors.New("serve failed")
					server.errors = serverErrors
					return server, nil
				}
			},
			wantContain: "callback server failed: serve failed",
		},
		{
			name: "timeout",
			configure: func(dependencies *browserFlowDependencies) {
				dependencies.startCallbackServer = func(chan<- browserCallbackResult) (*browserCallbackServer, error) {
					return newTestBrowserCallbackServer(CallbackPort), nil
				}
				dependencies.newTimer = func(time.Duration) browserFlowTimer {
					timer := &testBrowserFlowTimer{done: make(chan time.Time, 1)}
					timer.done <- time.Now()
					return timer
				}
			},
			wantContain: "authentication timed out",
		},
		{
			name: "callback server shutdown",
			configure: func(dependencies *browserFlowDependencies) {
				dependencies.startCallbackServer = func(results chan<- browserCallbackResult) (*browserCallbackServer, error) {
					results <- browserCallbackResult{code: testBrowserCode, state: testBrowserState}
					server := newTestBrowserCallbackServer(CallbackPort)
					server.shutdown = func(context.Context) error { return errors.New("shutdown failed") }
					return server, nil
				}
			},
			wantContain: "failed to stop callback server: shutdown failed",
		},
		{
			name: "provider callback error",
			configure: func(dependencies *browserFlowDependencies) {
				dependencies.startCallbackServer = func(results chan<- browserCallbackResult) (*browserCallbackServer, error) {
					results <- browserCallbackResult{errorCode: "access_denied", errorDescription: "cancelled"}
					return newTestBrowserCallbackServer(CallbackPort), nil
				}
			},
			wantContain: "access denied",
		},
		{
			name: "missing authorization code",
			configure: func(dependencies *browserFlowDependencies) {
				dependencies.startCallbackServer = func(results chan<- browserCallbackResult) (*browserCallbackServer, error) {
					results <- browserCallbackResult{state: testBrowserState}
					return newTestBrowserCallbackServer(CallbackPort), nil
				}
			},
			wantContain: "no authorization code received",
		},
		{
			name: "state mismatch",
			configure: func(dependencies *browserFlowDependencies) {
				dependencies.startCallbackServer = func(results chan<- browserCallbackResult) (*browserCallbackServer, error) {
					results <- browserCallbackResult{code: testBrowserCode, state: "unexpected-state"}
					return newTestBrowserCallbackServer(CallbackPort), nil
				}
			},
			wantContain: "security error: state parameter mismatch",
		},
		{
			name: "token exchange transport",
			configure: func(dependencies *browserFlowDependencies) {
				dependencies.newHTTPClient = func(bool) *http.Client {
					return newBrowserTokenClient(0, "", errors.New("connection failed"))
				}
			},
			wantContain: "token exchange failed",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dependencies := newTestBrowserFlowDependencies(io.Discard)
			test.configure(&dependencies)

			_, err := authenticateBrowserFlow(
				"https://oidc.example.com",
				"test-client",
				"openid",
				PKCEMethodS256,
				true,
				false,
				dependencies,
			)
			if err == nil || !strings.Contains(err.Error(), test.wantContain) {
				t.Errorf("authenticateBrowserFlow() error = %v, want containing %q", err, test.wantContain)
			}
		})
	}
}

func TestAuthenticateBrowserFlowStopsWaitResources(t *testing.T) {
	for _, test := range []struct {
		name             string
		configure        func(*browserFlowDependencies)
		wantProgressStop bool
		wantQuietStop    bool
	}{
		{
			name:             "callback",
			configure:        func(*browserFlowDependencies) {},
			wantProgressStop: true,
		},
		{
			name: "server error",
			configure: func(dependencies *browserFlowDependencies) {
				dependencies.startCallbackServer = func(chan<- browserCallbackResult) (*browserCallbackServer, error) {
					server := newTestBrowserCallbackServer(CallbackPort)
					serverErrors := make(chan error, 1)
					serverErrors <- errors.New("serve failed")
					server.errors = serverErrors
					return server, nil
				}
			},
			wantQuietStop: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			timer := &testBrowserFlowTimer{done: make(chan time.Time)}
			progress := &testBrowserFlowProgress{}
			dependencies := newTestBrowserFlowDependencies(io.Discard)
			dependencies.newTimer = func(time.Duration) browserFlowTimer { return timer }
			dependencies.newProgress = func() browserFlowProgress { return progress }
			test.configure(&dependencies)

			_, _ = authenticateBrowserFlow(
				"https://oidc.example.com",
				"test-client",
				"openid",
				PKCEMethodS256,
				true,
				false,
				dependencies,
			)

			if !timer.stopped {
				t.Error("authentication timer was not stopped")
			}
			if progress.stopped != test.wantProgressStop {
				t.Errorf("progress stopped = %v, want %v", progress.stopped, test.wantProgressStop)
			}
			if progress.stoppedQuiet != test.wantQuietStop {
				t.Errorf("progress stopped quietly = %v, want %v", progress.stoppedQuiet, test.wantQuietStop)
			}
		})
	}
}

func TestExchangeBrowserAuthorizationCode(t *testing.T) {
	tokenData := url.Values{"code": {testBrowserCode}}
	tests := []struct {
		name        string
		status      int
		body        string
		transport   error
		wantToken   string
		wantContain string
	}{
		{
			name:      "success",
			status:    http.StatusOK,
			body:      `{"access_token":"test-access-token"}`,
			wantToken: "test-access-token",
		},
		{
			name:        "transport error",
			transport:   errors.New("connection failed"),
			wantContain: "token exchange failed",
		},
		{
			name:        "non-OK OIDC response",
			status:      http.StatusBadRequest,
			body:        `{"error":"invalid_request","error_description":"missing code verifier"}`,
			wantContain: "invalid request: the authentication request was malformed. missing code verifier",
		},
		{
			name:        "non-OK plain response",
			status:      http.StatusBadGateway,
			body:        "upstream unavailable",
			wantContain: "token exchange failed with status 502: upstream unavailable",
		},
		{
			name:        "malformed response",
			status:      http.StatusOK,
			body:        `{`,
			wantContain: "failed to parse token response",
		},
		{
			name:        "OIDC error",
			status:      http.StatusOK,
			body:        `{"error":"invalid_grant","error_description":"expired code"}`,
			wantContain: "invalid or expired",
		},
		{
			name:        "missing access token",
			status:      http.StatusOK,
			body:        `{}`,
			wantContain: "no access token received",
		},
		{
			name:        "oversized response",
			status:      http.StatusOK,
			body:        strings.Repeat("x", maxOIDCResponseBodySize+1),
			wantContain: "OIDC response body exceeds 65536-byte limit",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token, err := exchangeBrowserAuthorizationCode(
				newBrowserTokenClient(test.status, test.body, test.transport),
				"https://oidc.example.com/token",
				tokenData,
				"https://oidc.example.com",
			)
			if token != test.wantToken {
				t.Errorf("token = %q, want %q", token, test.wantToken)
			}
			if test.wantContain == "" && err != nil {
				t.Errorf("exchangeBrowserAuthorizationCode() error = %v", err)
			}
			if test.wantContain != "" && (err == nil || !strings.Contains(err.Error(), test.wantContain)) {
				t.Errorf("exchangeBrowserAuthorizationCode() error = %v, want containing %q", err, test.wantContain)
			}
		})
	}
}

func TestExchangeBrowserAuthorizationCodeClosesResponseBody(t *testing.T) {
	body := &trackingReadCloser{Reader: strings.NewReader(`{"access_token":"test-access-token"}`)}
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       body,
		}, nil
	})}

	_, err := exchangeBrowserAuthorizationCode(
		client,
		"https://oidc.example.com/token",
		url.Values{},
		"https://oidc.example.com",
	)
	if err != nil {
		t.Fatalf("exchangeBrowserAuthorizationCode() error = %v", err)
	}
	if !body.closed {
		t.Error("token response body was not closed")
	}
}

func newTestBrowserFlowDependencies(stderr io.Writer) browserFlowDependencies {
	return browserFlowDependencies{
		stderr: stderr,
		generateRandomString: func(int) (string, error) {
			return testBrowserState, nil
		},
		generatePKCE: func(string) (string, string, string, error) {
			return testBrowserCodeVerifier, testBrowserCodeChallenge, PKCEMethodS256, nil
		},
		startCallbackServer: func(results chan<- browserCallbackResult) (*browserCallbackServer, error) {
			results <- browserCallbackResult{code: testBrowserCode, state: testBrowserState}
			return newTestBrowserCallbackServer(CallbackPort), nil
		},
		openBrowser: func(string) error { return nil },
		newHTTPClient: func(bool) *http.Client {
			return newBrowserTokenClient(http.StatusOK, `{"access_token":"test-access-token"}`, nil)
		},
		discoverEndpoints: func(*http.Client, string) (oidcEndpoints, error) {
			return oidcEndpoints{
				authorization: "https://oidc.example.com/authorize",
				token:         "https://oidc.example.com/token",
			}, nil
		},
		newTimer: func(time.Duration) browserFlowTimer {
			return &testBrowserFlowTimer{done: make(chan time.Time)}
		},
		newProgress: func() browserFlowProgress { return &testBrowserFlowProgress{} },
	}
}

func newTestBrowserCallbackServer(port int) *browserCallbackServer {
	return &browserCallbackServer{
		port:     port,
		errors:   make(chan error),
		shutdown: func(context.Context) error { return nil },
		close:    func() error { return nil },
	}
}

func newBrowserTokenClient(status int, body string, transportError error) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		if transportError != nil {
			return nil, transportError
		}
		return &http.Response{
			StatusCode: status,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
		}, nil
	})}
}

func TestListenOnCallbackPorts(t *testing.T) {
	t.Run("keeps selected port reserved", func(t *testing.T) {
		listener, port, err := listenOnCallbackPorts("127.0.0.1", 0)
		if err != nil {
			t.Fatalf("listenOnCallbackPorts() error = %v", err)
		}
		t.Cleanup(func() { _ = listener.Close() })

		duplicate, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			_ = duplicate.Close()
			t.Fatal("selected callback port was not kept reserved")
		}
	})

	t.Run("falls back when first port is busy", func(t *testing.T) {
		occupied, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to occupy first port: %v", err)
		}
		t.Cleanup(func() { _ = occupied.Close() })
		occupiedPort := occupied.Addr().(*net.TCPAddr).Port

		listener, port, err := listenOnCallbackPorts("127.0.0.1", occupiedPort, 0)
		if err != nil {
			t.Fatalf("listenOnCallbackPorts() error = %v", err)
		}
		t.Cleanup(func() { _ = listener.Close() })

		if port == occupiedPort {
			t.Errorf("selected port = %d, want a fallback port", port)
		}
	})

	t.Run("reports when all ports are busy", func(t *testing.T) {
		first, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to occupy first port: %v", err)
		}
		t.Cleanup(func() { _ = first.Close() })

		second, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to occupy second port: %v", err)
		}
		t.Cleanup(func() { _ = second.Close() })

		_, _, err = listenOnCallbackPorts(
			"127.0.0.1",
			first.Addr().(*net.TCPAddr).Port,
			second.Addr().(*net.TCPAddr).Port,
		)
		if err == nil {
			t.Fatal("listenOnCallbackPorts() expected an error")
		}
	})

	t.Run("rejects an empty port list", func(t *testing.T) {
		_, _, err := listenOnCallbackPorts("127.0.0.1")
		if err == nil {
			t.Fatal("listenOnCallbackPorts() expected an error")
		}
	})
}

func TestBrowserCallbackHandler(t *testing.T) {
	t.Run("delivers authorization code", func(t *testing.T) {
		results := make(chan browserCallbackResult, 1)
		handler := newBrowserCallbackHandler(results)
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/callback?code=test-code&state=test-state", nil)

		handler.ServeHTTP(response, request)

		if response.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", response.Code, http.StatusOK)
		}
		result := <-results
		if result.code != "test-code" || result.state != "test-state" {
			t.Errorf("result = %+v, want code and state", result)
		}
	})

	t.Run("delivers provider error and escapes response", func(t *testing.T) {
		results := make(chan browserCallbackResult, 1)
		handler := newBrowserCallbackHandler(results)
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/callback?error=access_denied&error_description=%3Cscript%3Ealert(1)%3C/script%3E", nil)

		handler.ServeHTTP(response, request)

		if response.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", response.Code, http.StatusBadRequest)
		}
		if strings.Contains(response.Body.String(), "<script>alert(1)</script>") {
			t.Error("error description was not HTML-escaped")
		}
		result := <-results
		if result.errorCode != "access_denied" || result.errorDescription != "<script>alert(1)</script>" {
			t.Errorf("result = %+v, want provider error", result)
		}
	})

	t.Run("rejects incomplete callback without completing flow", func(t *testing.T) {
		results := make(chan browserCallbackResult, 1)
		handler := newBrowserCallbackHandler(results)
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/callback?code=test-code", nil)

		handler.ServeHTTP(response, request)

		if response.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", response.Code, http.StatusBadRequest)
		}
		if len(results) != 0 {
			t.Error("incomplete callback completed the flow")
		}
	})

	t.Run("duplicate callback does not block", func(t *testing.T) {
		results := make(chan browserCallbackResult, 1)
		handler := newBrowserCallbackHandler(results)
		handler.ServeHTTP(
			httptest.NewRecorder(),
			httptest.NewRequest(http.MethodGet, "/callback?code=first&state=test-state", nil),
		)

		done := make(chan struct{})
		go func() {
			handler.ServeHTTP(
				httptest.NewRecorder(),
				httptest.NewRequest(http.MethodGet, "/callback?code=second&state=test-state", nil),
			)
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("duplicate callback blocked")
		}

		result := <-results
		if result.code != "first" {
			t.Errorf("result code = %q, want first", result.code)
		}
	})
}
