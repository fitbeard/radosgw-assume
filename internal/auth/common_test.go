package auth

import (
	"errors"
	"net/http"
	"net/url"
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
	tests := []struct {
		name          string
		sslVerify     bool
		wantTransport bool
	}{
		{
			name:          "SSL verification enabled",
			sslVerify:     true,
			wantTransport: false,
		},
		{
			name:          "SSL verification disabled",
			sslVerify:     false,
			wantTransport: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewHTTPClient(tt.sslVerify)
			if client == nil {
				t.Fatal("NewHTTPClient returned nil")
			}

			hasTransport := client.Transport != nil
			if hasTransport != tt.wantTransport {
				t.Errorf("NewHTTPClient transport = %v, want transport = %v", hasTransport, tt.wantTransport)
			}
			if client.Timeout != OIDCRequestTimeout {
				t.Errorf("NewHTTPClient timeout = %v, want %v", client.Timeout, OIDCRequestTimeout)
			}

			if tt.wantTransport {
				// Verify it's an http.Transport with TLS config
				transport, ok := client.Transport.(*http.Transport)
				if !ok {
					t.Error("Expected *http.Transport when SSL verification is disabled")
				} else if transport.TLSClientConfig == nil {
					t.Error("Expected TLSClientConfig to be set when SSL verification is disabled")
				} else if !transport.TLSClientConfig.InsecureSkipVerify {
					t.Error("Expected InsecureSkipVerify to be true when SSL verification is disabled")
				}
			}
		})
	}
}

func TestHTTPClientTimeout(t *testing.T) {
	const requestTimeout = 10 * time.Millisecond
	client := newHTTPClient(true, requestTimeout)
	client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		select {
		case <-request.Context().Done():
			return nil, request.Context().Err()
		case <-time.After(time.Second):
			return nil, errors.New("request context was not cancelled")
		}
	})

	response, err := client.Get("http://oidc.example.com")
	if response != nil {
		defer func() { _ = response.Body.Close() }()
	}
	if err == nil {
		t.Fatal("HTTP request expected a timeout error")
	}

	var urlError *url.Error
	if !errors.As(err, &urlError) || !urlError.Timeout() {
		t.Errorf("HTTP request error = %v, want a timeout", err)
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
			name:        "access_denied",
			errorCode:   "access_denied",
			errorDesc:   "",
			wantContain: "denied",
		},
		{
			name:        "server_error",
			errorCode:   "server_error",
			errorDesc:   "",
			wantContain: "internal error",
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
