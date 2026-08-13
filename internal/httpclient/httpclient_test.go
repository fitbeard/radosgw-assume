package httpclient

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestNew(t *testing.T) {
	const requestTimeout = 15 * time.Second
	tests := []struct {
		name          string
		verifyTLS     bool
		wantTransport bool
	}{
		{
			name:          "TLS verification enabled",
			verifyTLS:     true,
			wantTransport: false,
		},
		{
			name:          "TLS verification disabled",
			verifyTLS:     false,
			wantTransport: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := New(tt.verifyTLS, requestTimeout)
			if client.Timeout != requestTimeout {
				t.Errorf("client timeout = %v, want %v", client.Timeout, requestTimeout)
			}

			hasTransport := client.Transport != nil
			if hasTransport != tt.wantTransport {
				t.Errorf("client transport configured = %v, want %v", hasTransport, tt.wantTransport)
			}
			if !tt.wantTransport {
				return
			}

			transport, ok := client.Transport.(*http.Transport)
			if !ok {
				t.Fatalf("client transport = %T, want *http.Transport", client.Transport)
			}
			if transport.TLSClientConfig == nil || !transport.TLSClientConfig.InsecureSkipVerify {
				t.Fatal("client transport did not disable TLS verification")
			}
			assertClonedDefaultTransport(t, transport)
		})
	}
}

func assertClonedDefaultTransport(t *testing.T, transport *http.Transport) {
	t.Helper()

	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Skip("http.DefaultTransport is not an *http.Transport")
	}
	if transport == defaultTransport {
		t.Error("insecure transport must not mutate http.DefaultTransport")
	}
	if transport.Proxy == nil && defaultTransport.Proxy != nil {
		t.Error("insecure transport did not preserve proxy configuration")
	}
	if transport.ForceAttemptHTTP2 != defaultTransport.ForceAttemptHTTP2 {
		t.Errorf("ForceAttemptHTTP2 = %v, want %v", transport.ForceAttemptHTTP2, defaultTransport.ForceAttemptHTTP2)
	}
	if transport.MaxIdleConns != defaultTransport.MaxIdleConns {
		t.Errorf("MaxIdleConns = %d, want %d", transport.MaxIdleConns, defaultTransport.MaxIdleConns)
	}
	if transport.IdleConnTimeout != defaultTransport.IdleConnTimeout {
		t.Errorf("IdleConnTimeout = %v, want %v", transport.IdleConnTimeout, defaultTransport.IdleConnTimeout)
	}
	if transport.TLSHandshakeTimeout != defaultTransport.TLSHandshakeTimeout {
		t.Errorf("TLSHandshakeTimeout = %v, want %v", transport.TLSHandshakeTimeout, defaultTransport.TLSHandshakeTimeout)
	}
}

func TestNewUsesIndependentTLSConfigurations(t *testing.T) {
	firstTransport := New(false, time.Second).Transport.(*http.Transport)
	secondTransport := New(false, time.Second).Transport.(*http.Transport)

	firstTransport.TLSClientConfig.ServerName = "first.example.com"
	if secondTransport.TLSClientConfig.ServerName != "" {
		t.Errorf("second TLS server name = %q, want empty", secondTransport.TLSClientConfig.ServerName)
	}
}

func TestNewClonesDefaultTLSConfiguration(t *testing.T) {
	originalDefault := http.DefaultTransport
	defaultTransport, ok := originalDefault.(*http.Transport)
	if !ok {
		t.Skip("http.DefaultTransport is not an *http.Transport")
	}

	customDefault := defaultTransport.Clone()
	customDefault.TLSClientConfig = &tls.Config{ServerName: "default.example.com"}
	http.DefaultTransport = customDefault
	t.Cleanup(func() { http.DefaultTransport = originalDefault })

	transport := New(false, time.Second).Transport.(*http.Transport)
	if transport.TLSClientConfig == customDefault.TLSClientConfig {
		t.Fatal("client transport reused the default TLS configuration")
	}
	if transport.TLSClientConfig.ServerName != customDefault.TLSClientConfig.ServerName {
		t.Errorf("TLS server name = %q, want %q", transport.TLSClientConfig.ServerName, customDefault.TLSClientConfig.ServerName)
	}
	if !transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("client transport did not disable TLS verification")
	}
}

func TestNewHandlesCustomDefaultRoundTripper(t *testing.T) {
	originalDefault := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("custom default transport should not be called")
	})
	t.Cleanup(func() { http.DefaultTransport = originalDefault })

	transport := New(false, time.Second).Transport.(*http.Transport)
	if transport.Proxy == nil {
		t.Fatal("fallback transport did not configure environment proxy support")
	}
	if transport.TLSClientConfig == nil || !transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("fallback transport did not disable TLS verification")
	}
}

func TestClientTimeout(t *testing.T) {
	const requestTimeout = 10 * time.Millisecond
	client := New(true, requestTimeout)
	client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		select {
		case <-request.Context().Done():
			return nil, request.Context().Err()
		case <-time.After(time.Second):
			return nil, errors.New("request context was not cancelled")
		}
	})

	response, err := client.Get("http://service.example.com")
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
