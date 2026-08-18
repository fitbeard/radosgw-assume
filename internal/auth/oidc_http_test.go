package auth

import (
	"net/http"
	"strings"
	"testing"
)

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
