package auth

import (
	"bytes"
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

func TestEndpointsForProvider(t *testing.T) {
	tests := []struct {
		name        string
		providerURL string
		baseURL     string
	}{
		{
			name:        "provider URL",
			providerURL: "https://oidc.example.com/realms/test",
			baseURL:     "https://oidc.example.com/realms/test",
		},
		{
			name:        "trailing slash",
			providerURL: "https://oidc.example.com/realms/test/",
			baseURL:     "https://oidc.example.com/realms/test",
		},
		{
			name:        "multiple trailing slashes",
			providerURL: "https://oidc.example.com/realms/test///",
			baseURL:     "https://oidc.example.com/realms/test",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			endpoints := endpointsForProvider(test.providerURL)
			protocolURL := test.baseURL + "/protocol/openid-connect"

			if endpoints.authorization != protocolURL+"/auth" {
				t.Errorf("authorization endpoint = %q, want %q", endpoints.authorization, protocolURL+"/auth")
			}
			if endpoints.deviceAuthorization != protocolURL+"/auth/device" {
				t.Errorf("device authorization endpoint = %q, want %q", endpoints.deviceAuthorization, protocolURL+"/auth/device")
			}
			if endpoints.token != protocolURL+"/token" {
				t.Errorf("token endpoint = %q, want %q", endpoints.token, protocolURL+"/token")
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
