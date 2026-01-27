package auth

import (
	"net/http"
	"strings"
	"testing"
)

func TestNewHTTPClient(t *testing.T) {
	tests := []struct {
		name           string
		sslVerify      bool
		wantTransport  bool
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

	if ProgressInterval <= 0 {
		t.Errorf("ProgressInterval should be positive, got %v", ProgressInterval)
	}

	if DefaultPollingInterval <= 0 {
		t.Errorf("DefaultPollingInterval should be positive, got %d", DefaultPollingInterval)
	}

	if ServerStartTimeout <= 0 {
		t.Errorf("ServerStartTimeout should be positive, got %v", ServerStartTimeout)
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
