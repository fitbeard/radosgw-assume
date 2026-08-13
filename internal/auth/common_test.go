package auth

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestNewHTTPClient(t *testing.T) {
	client := NewHTTPClient(false)
	if client.Timeout != OIDCRequestTimeout {
		t.Errorf("NewHTTPClient timeout = %v, want %v", client.Timeout, OIDCRequestTimeout)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("NewHTTPClient transport = %T, want *http.Transport", client.Transport)
	}
	if transport.TLSClientConfig == nil || !transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("NewHTTPClient did not disable TLS verification")
	}
}

func TestDiscoverOIDCEndpoints(t *testing.T) {
	const issuer = "https://oidc.example.com/oauth2/default"
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if got, want := request.URL.String(), issuer+"/.well-known/openid-configuration"; got != want {
			t.Errorf("discovery URL = %q, want %q", got, want)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body: io.NopCloser(strings.NewReader(`{
				"issuer":"https://oidc.example.com/oauth2/default",
				"authorization_endpoint":"https://oidc.example.com/oauth2/default/v1/authorize?audience=storage",
				"device_authorization_endpoint":"https://oidc.example.com/oauth2/default/v1/device/authorize",
				"token_endpoint":"https://oidc.example.com/oauth2/default/v1/token"
			}`)),
		}, nil
	})}

	endpoints, err := discoverOIDCEndpoints(client, issuer+"///")
	if err != nil {
		t.Fatalf("discoverOIDCEndpoints() error = %v", err)
	}
	if endpoints.authorization != issuer+"/v1/authorize?audience=storage" {
		t.Errorf("authorization endpoint = %q", endpoints.authorization)
	}
	if endpoints.deviceAuthorization != issuer+"/v1/device/authorize" {
		t.Errorf("device authorization endpoint = %q", endpoints.deviceAuthorization)
	}
	if endpoints.token != issuer+"/v1/token" {
		t.Errorf("token endpoint = %q", endpoints.token)
	}
}

func TestDiscoverOIDCEndpointsErrors(t *testing.T) {
	const issuer = "https://oidc.example.com/oauth2/default"
	tests := []struct {
		name        string
		providerURL string
		status      int
		body        string
		transport   error
		wantContain string
	}{
		{
			name:        "invalid provider URL",
			providerURL: "oidc.example.com/oauth2/default",
			wantContain: "URL must be absolute",
		},
		{
			name:        "provider URL query",
			providerURL: issuer + "?tenant=test",
			wantContain: "query and fragment are not allowed",
		},
		{
			name:        "provider URL user information",
			providerURL: "https://user@oidc.example.com/oauth2/default",
			wantContain: "user information is not allowed",
		},
		{
			name:        "transport error",
			providerURL: issuer,
			transport:   errors.New("connection failed"),
			wantContain: "OIDC discovery request failed",
		},
		{
			name:        "provider status",
			providerURL: issuer,
			status:      http.StatusBadGateway,
			body:        "upstream unavailable",
			wantContain: "OIDC discovery failed with status 502: upstream unavailable",
		},
		{
			name:        "malformed response",
			providerURL: issuer,
			status:      http.StatusOK,
			body:        `{`,
			wantContain: "failed to parse OIDC discovery response",
		},
		{
			name:        "issuer mismatch",
			providerURL: issuer,
			status:      http.StatusOK,
			body:        `{"issuer":"https://other.example.com","token_endpoint":"https://oidc.example.com/token"}`,
			wantContain: "OIDC discovery issuer mismatch",
		},
		{
			name:        "relative endpoint",
			providerURL: issuer,
			status:      http.StatusOK,
			body:        `{"issuer":"https://oidc.example.com/oauth2/default","token_endpoint":"/v1/token"}`,
			wantContain: "token_endpoint \"/v1/token\": URL must be absolute",
		},
		{
			name:        "endpoint fragment",
			providerURL: issuer,
			status:      http.StatusOK,
			body:        `{"issuer":"https://oidc.example.com/oauth2/default","token_endpoint":"https://oidc.example.com/token#fragment"}`,
			wantContain: "fragment is not allowed",
		},
		{
			name:        "endpoint scheme downgrade",
			providerURL: issuer,
			status:      http.StatusOK,
			body:        `{"issuer":"https://oidc.example.com/oauth2/default","token_endpoint":"http://oidc.example.com/token"}`,
			wantContain: "HTTPS issuer endpoints must use https",
		},
		{
			name:        "endpoint user information",
			providerURL: issuer,
			status:      http.StatusOK,
			body:        `{"issuer":"https://oidc.example.com/oauth2/default","token_endpoint":"https://user@oidc.example.com/token"}`,
			wantContain: "user information is not allowed",
		},
		{
			name:        "oversized response",
			providerURL: issuer,
			status:      http.StatusOK,
			body:        strings.Repeat("x", maxOIDCResponseBodySize+1),
			wantContain: "OIDC response body exceeds 65536-byte limit",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				if test.transport != nil {
					return nil, test.transport
				}
				return &http.Response{
					StatusCode: test.status,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(test.body)),
				}, nil
			})}

			_, err := discoverOIDCEndpoints(client, test.providerURL)
			if err == nil || !strings.Contains(err.Error(), test.wantContain) {
				t.Errorf("discoverOIDCEndpoints() error = %v, want containing %q", err, test.wantContain)
			}
		})
	}
}

func TestOIDCEndpointRequirements(t *testing.T) {
	tests := []struct {
		name        string
		validate    func(oidcEndpoints) error
		endpoints   oidcEndpoints
		wantContain string
	}{
		{
			name:        "browser authorization endpoint",
			validate:    oidcEndpoints.validateBrowserFlow,
			endpoints:   oidcEndpoints{token: "https://oidc.example.com/token"},
			wantContain: "authorization_endpoint",
		},
		{
			name:        "browser token endpoint",
			validate:    oidcEndpoints.validateBrowserFlow,
			endpoints:   oidcEndpoints{authorization: "https://oidc.example.com/authorize"},
			wantContain: "token_endpoint",
		},
		{
			name:        "device authorization endpoint",
			validate:    oidcEndpoints.validateDeviceFlow,
			endpoints:   oidcEndpoints{token: "https://oidc.example.com/token"},
			wantContain: "device_authorization_endpoint",
		},
		{
			name:        "device token endpoint",
			validate:    oidcEndpoints.validateDeviceFlow,
			endpoints:   oidcEndpoints{deviceAuthorization: "https://oidc.example.com/device"},
			wantContain: "token_endpoint",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.validate(test.endpoints)
			if err == nil || !strings.Contains(err.Error(), test.wantContain) {
				t.Errorf("endpoint validation error = %v, want containing %q", err, test.wantContain)
			}
		})
	}
}

func TestProgressIndicator(t *testing.T) {
	tests := []struct {
		name       string
		stop       func(*ProgressIndicator)
		stopAgain  func(*ProgressIndicator)
		emitTick   bool
		wantOutput string
	}{
		{
			name:       "normal stop",
			stop:       (*ProgressIndicator).Stop,
			stopAgain:  (*ProgressIndicator).StopQuiet,
			emitTick:   true,
			wantOutput: "#\n",
		},
		{
			name:       "quiet stop",
			stop:       (*ProgressIndicator).StopQuiet,
			stopAgain:  (*ProgressIndicator).Stop,
			wantOutput: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ticks := make(chan time.Time, 1)
			output := newProgressTestWriter()
			var tickerStops atomic.Int32
			progress := newProgressIndicator(output, ticks, func() { tickerStops.Add(1) })

			if test.emitTick {
				ticks <- time.Now()
				select {
				case write := <-output.writes:
					if write != "#" {
						t.Errorf("progress write = %q, want #", write)
					}
				case <-time.After(time.Second):
					t.Fatal("progress indicator did not render a tick")
				}
			}

			test.stop(progress)
			test.stop(progress)
			test.stopAgain(progress)

			if got := output.String(); got != test.wantOutput {
				t.Errorf("progress output = %q, want %q", got, test.wantOutput)
			}
			if got := tickerStops.Load(); got != 1 {
				t.Errorf("ticker stops = %d, want 1", got)
			}
		})
	}
}

func TestProgressIndicatorConcurrentStops(t *testing.T) {
	output := newProgressTestWriter()
	var tickerStops atomic.Int32
	progress := newProgressIndicator(
		output,
		make(chan time.Time),
		func() { tickerStops.Add(1) },
	)

	const callers = 20
	start := make(chan struct{})
	var waitGroup sync.WaitGroup
	for caller := 0; caller < callers; caller++ {
		waitGroup.Add(1)
		go func(quiet bool) {
			defer waitGroup.Done()
			<-start
			if quiet {
				progress.StopQuiet()
				return
			}
			progress.Stop()
		}(caller%2 == 0)
	}
	close(start)

	done := make(chan struct{})
	go func() {
		waitGroup.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("concurrent progress stops blocked")
	}

	if got := tickerStops.Load(); got != 1 {
		t.Errorf("ticker stops = %d, want 1", got)
	}
	if got := output.String(); got != "" && got != "\n" {
		t.Errorf("progress output = %q, want empty or one newline", got)
	}
}

func TestNewProgressIndicatorStops(t *testing.T) {
	progress := NewProgressIndicator()
	progress.StopQuiet()
	progress.StopQuiet()
}

type progressTestWriter struct {
	mutex  sync.Mutex
	output strings.Builder
	writes chan string
}

func newProgressTestWriter() *progressTestWriter {
	return &progressTestWriter{writes: make(chan string, 32)}
}

func (writer *progressTestWriter) Write(value []byte) (int, error) {
	writer.mutex.Lock()
	defer writer.mutex.Unlock()
	_, _ = writer.output.Write(value)
	writer.writes <- string(value)
	return len(value), nil
}

func (writer *progressTestWriter) String() string {
	writer.mutex.Lock()
	defer writer.mutex.Unlock()
	return writer.output.String()
}

func TestGenerateRandomString(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{
			name:   "short string",
			length: 8,
		},
		{
			name:   "medium string",
			length: 32,
		},
		{
			name:   "long string",
			length: 96,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := GenerateRandomString(tt.length)
			if err != nil {
				t.Fatalf("GenerateRandomString returned error: %v", err)
			}

			if len(result) != tt.length {
				t.Errorf("GenerateRandomString length = %d, want %d", len(result), tt.length)
			}

			// Verify all characters are alphanumeric
			for i, c := range result {
				isLower := c >= 'a' && c <= 'z'
				isUpper := c >= 'A' && c <= 'Z'
				isDigit := c >= '0' && c <= '9'
				if !isLower && !isUpper && !isDigit {
					t.Errorf("GenerateRandomString contains invalid character at position %d: %c", i, c)
				}
			}
		})
	}
}

func TestGenerateRandomStringRejectsBiasedBytes(t *testing.T) {
	randomBytes := bytes.NewReader([]byte{0, 61, 248, 255, 62, 247})

	result, err := generateRandomString(4, randomBytes)
	if err != nil {
		t.Fatalf("generateRandomString() error = %v", err)
	}
	if result != "a9a9" {
		t.Errorf("generateRandomString() = %q, want %q", result, "a9a9")
	}
}

func TestGenerateRandomStringLengths(t *testing.T) {
	result, err := generateRandomString(0, strings.NewReader(""))
	if err != nil {
		t.Fatalf("generateRandomString(0) error = %v", err)
	}
	if result != "" {
		t.Errorf("generateRandomString(0) = %q, want empty", result)
	}

	_, err = generateRandomString(-1, strings.NewReader(""))
	if err == nil || !strings.Contains(err.Error(), "length cannot be negative") {
		t.Errorf("generateRandomString(-1) error = %v, want negative length error", err)
	}
}

func TestGenerateRandomStringReadError(t *testing.T) {
	_, err := generateRandomString(2, strings.NewReader("a"))
	if err == nil || !strings.Contains(err.Error(), "failed to generate random bytes") {
		t.Errorf("generateRandomString() error = %v, want wrapped read error", err)
	}
}

func TestGenerateRandomString_Uniqueness(t *testing.T) {
	// Generate multiple strings and verify they're different
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		s, err := GenerateRandomString(32)
		if err != nil {
			t.Fatalf("GenerateRandomString returned error: %v", err)
		}
		if seen[s] {
			t.Errorf("GenerateRandomString produced duplicate string: %s", s)
		}
		seen[s] = true
	}
}

func TestFormatOIDCError(t *testing.T) {
	providerURL := "https://keycloak.example.com/realms/test"

	tests := []struct {
		name        string
		errorCode   string
		errorDesc   string
		wantContain string
	}{
		{
			name:        "invalid_request",
			errorCode:   "invalid_request",
			errorDesc:   "missing parameter",
			wantContain: "authentication request was malformed. missing parameter",
		},
		{
			name:        "invalid_client",
			errorCode:   "invalid_client",
			errorDesc:   "",
			wantContain: "client ID is not recognized",
		},
		{
			name:        "invalid_grant",
			errorCode:   "invalid_grant",
			errorDesc:   "",
			wantContain: "invalid or expired",
		},
		{
			name:        "unauthorized_client",
			errorCode:   "unauthorized_client",
			wantContain: "not authorized for the requested authentication flow",
		},
		{
			name:        "unsupported_grant_type",
			errorCode:   "unsupported_grant_type",
			wantContain: "does not support this authentication method",
		},
		{
			name:        "invalid_scope",
			errorCode:   "invalid_scope",
			errorDesc:   "groups",
			wantContain: "requested scope 'groups' is not valid",
		},
		{
			name:        "access_denied",
			errorCode:   "access_denied",
			errorDesc:   "",
			wantContain: "denied",
		},
		{
			name:        "expired_token",
			errorCode:   "expired_token",
			wantContain: "device code has expired",
		},
		{
			name:        "server_error",
			errorCode:   "server_error",
			errorDesc:   "",
			wantContain: "internal error",
		},
		{
			name:        "temporarily_unavailable",
			errorCode:   "temporarily_unavailable",
			wantContain: "currently unavailable",
		},
		{
			name:        "unknown error with description",
			errorCode:   "custom_error",
			errorDesc:   "Something went wrong",
			wantContain: "Something went wrong",
		},
		{
			name:        "unknown error without description",
			errorCode:   "custom_error",
			errorDesc:   "",
			wantContain: "custom_error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := FormatOIDCError(tt.errorCode, tt.errorDesc, providerURL)
			if err == nil {
				t.Fatal("FormatOIDCError returned nil, expected error")
			}
			if !strings.Contains(err.Error(), tt.wantContain) {
				t.Errorf("FormatOIDCError() = %v, want to contain %v", err, tt.wantContain)
			}
		})
	}
}

func TestOIDCHTTPStatusErrorDetails(t *testing.T) {
	t.Run("uses status text for empty body", func(t *testing.T) {
		err := oidcHTTPStatusError("token request", http.StatusBadGateway, nil, "https://oidc.example.com")
		if !strings.Contains(err.Error(), "token request failed with status 502: Bad Gateway") {
			t.Errorf("oidcHTTPStatusError() = %v", err)
		}
	})

	t.Run("handles unknown status with empty body", func(t *testing.T) {
		err := oidcHTTPStatusError("token request", 799, nil, "https://oidc.example.com")
		if !strings.Contains(err.Error(), "empty response body") {
			t.Errorf("oidcHTTPStatusError() = %v", err)
		}
	})

	t.Run("truncates plain response detail", func(t *testing.T) {
		detail := strings.Repeat("x", maxOIDCErrorDetailSize+1)
		err := oidcHTTPStatusError("token request", http.StatusBadGateway, []byte(detail), "https://oidc.example.com")
		if strings.Contains(err.Error(), detail) || !strings.HasSuffix(err.Error(), "…") {
			t.Errorf("oidcHTTPStatusError() did not truncate detail: %v", err)
		}
	})
}

func TestConstants(t *testing.T) {
	// Verify constants have sensible values
	if AuthTimeout <= 0 {
		t.Errorf("AuthTimeout should be positive, got %v", AuthTimeout)
	}

	if OIDCRequestTimeout <= 0 {
		t.Errorf("OIDCRequestTimeout should be positive, got %v", OIDCRequestTimeout)
	}

	if ProgressInterval <= 0 {
		t.Errorf("ProgressInterval should be positive, got %v", ProgressInterval)
	}

	if DefaultPollingInterval <= 0 {
		t.Errorf("DefaultPollingInterval should be positive, got %d", DefaultPollingInterval)
	}

	if CallbackReadHeaderTimeout <= 0 {
		t.Errorf("CallbackReadHeaderTimeout should be positive, got %v", CallbackReadHeaderTimeout)
	}

	if CallbackShutdownTimeout <= 0 {
		t.Errorf("CallbackShutdownTimeout should be positive, got %v", CallbackShutdownTimeout)
	}

	if maxOIDCResponseBodySize <= 0 {
		t.Errorf("maxOIDCResponseBodySize should be positive, got %d", maxOIDCResponseBodySize)
	}

	if maxOIDCErrorDetailSize <= 0 || maxOIDCErrorDetailSize > maxOIDCResponseBodySize {
		t.Errorf("maxOIDCErrorDetailSize should be positive and bounded by the response limit, got %d", maxOIDCErrorDetailSize)
	}

	if CallbackPort <= 0 || CallbackPort > 65535 {
		t.Errorf("CallbackPort should be valid port number, got %d", CallbackPort)
	}

	if CallbackFallbackPort <= 0 || CallbackFallbackPort > 65535 {
		t.Errorf("CallbackFallbackPort should be valid port number, got %d", CallbackFallbackPort)
	}

	if CallbackPort == CallbackFallbackPort {
		t.Error("CallbackPort and CallbackFallbackPort should be different")
	}
}
