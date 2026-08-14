package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Note: These tests focus on struct validation and type checking
// rather than network operations to ensure CI/CD compatibility

func TestDeviceAuthResponse(t *testing.T) {
	// Test the DeviceAuthResponse struct
	response := DeviceAuthResponse{
		DeviceCode:              "test-device-code",
		UserCode:                "TEST-CODE",
		VerificationURI:         "https://example.com/device",
		VerificationURIComplete: "https://example.com/device?user_code=TEST-CODE",
		ExpiresIn:               600,
		Interval:                5,
	}

	if response.DeviceCode != "test-device-code" {
		t.Errorf("DeviceAuthResponse.DeviceCode = %s, want test-device-code", response.DeviceCode)
	}
	if response.UserCode != "TEST-CODE" {
		t.Errorf("DeviceAuthResponse.UserCode = %s, want TEST-CODE", response.UserCode)
	}
	if response.ExpiresIn != 600 {
		t.Errorf("DeviceAuthResponse.ExpiresIn = %d, want 600", response.ExpiresIn)
	}
}

func TestTokenResponse(t *testing.T) {
	// Test the TokenResponse struct
	response := TokenResponse{
		AccessToken:  "test-access-token",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: "test-refresh-token",
	}

	if response.AccessToken != "test-access-token" {
		t.Errorf("TokenResponse.AccessToken = %s, want test-access-token", response.AccessToken)
	}
	if response.TokenType != "Bearer" {
		t.Errorf("TokenResponse.TokenType = %s, want Bearer", response.TokenType)
	}
	if response.ExpiresIn != 3600 {
		t.Errorf("TokenResponse.ExpiresIn = %d, want 3600", response.ExpiresIn)
	}
}

func TestTokenResponse_WithError(t *testing.T) {
	// Test the TokenResponse struct with error fields
	response := TokenResponse{
		Error:     "invalid_request",
		ErrorDesc: "The request is missing a required parameter",
	}

	if response.Error != "invalid_request" {
		t.Errorf("TokenResponse.Error = %s, want invalid_request", response.Error)
	}
	if response.ErrorDesc != "The request is missing a required parameter" {
		t.Errorf("TokenResponse.ErrorDesc = %s, want 'The request is missing a required parameter'", response.ErrorDesc)
	}
}

func TestAuthenticateDeviceFlow(t *testing.T) {
	for _, pkceMethod := range []string{PKCEMethodS256, PKCEMethodPlain} {
		t.Run(pkceMethod, func(t *testing.T) {
			var tokenRequests atomic.Int32
			var codeChallenge atomic.Value
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/.well-known/openid-configuration":
					_ = json.NewEncoder(w).Encode(oidcProviderMetadata{
						Issuer:                      serverURL(r),
						AuthorizationEndpoint:       serverURL(r) + "/oauth2/default/v1/authorize",
						DeviceAuthorizationEndpoint: serverURL(r) + "/oauth2/default/v1/device/authorize",
						TokenEndpoint:               serverURL(r) + "/oauth2/default/v1/token",
					})
				case "/oauth2/default/v1/device/authorize":
					if err := r.ParseForm(); err != nil {
						t.Errorf("ParseForm() error = %v", err)
					}
					if got := r.Form.Get("client_id"); got != "test-client" {
						t.Errorf("client_id = %q, want test-client", got)
					}
					if got := r.Form.Get("scope"); got != "openid profile" {
						t.Errorf("scope = %q, want openid profile", got)
					}
					if got := r.Form.Get("code_challenge_method"); got != pkceMethod {
						t.Errorf("code_challenge_method = %q, want %q", got, pkceMethod)
					}
					challenge := r.Form.Get("code_challenge")
					if challenge == "" {
						t.Error("code_challenge is empty")
					}
					codeChallenge.Store(challenge)
					_ = json.NewEncoder(w).Encode(DeviceAuthResponse{
						DeviceCode:      "test-device-code",
						UserCode:        "TEST-CODE",
						VerificationURI: serverURL(r),
						ExpiresIn:       600,
						Interval:        1,
					})
				case "/oauth2/default/v1/token":
					requestNumber := tokenRequests.Add(1)
					if err := r.ParseForm(); err != nil {
						t.Errorf("ParseForm() error = %v", err)
					}
					if got := r.Form.Get("device_code"); got != "test-device-code" {
						t.Errorf("device_code = %q, want test-device-code", got)
					}

					verifier := r.Form.Get("code_verifier")
					wantChallenge := verifier
					if pkceMethod == PKCEMethodS256 {
						hash := sha256.Sum256([]byte(verifier))
						wantChallenge = base64.RawURLEncoding.EncodeToString(hash[:])
					}
					if got := codeChallenge.Load(); got != wantChallenge {
						t.Errorf("challenge for verifier = %q, want %q", got, wantChallenge)
					}

					if requestNumber == 1 {
						w.WriteHeader(http.StatusBadRequest)
						_ = json.NewEncoder(w).Encode(TokenResponse{Error: "authorization_pending"})
						return
					}
					_ = json.NewEncoder(w).Encode(TokenResponse{AccessToken: "test-access-token"})
				default:
					http.NotFound(w, r)
				}
			}))
			t.Cleanup(server.Close)

			currentTime := time.Unix(0, 0)
			dependencies := newDeviceFlowDependencies()
			dependencies.stderr = io.Discard
			dependencies.newHTTPClient = func(sslVerify bool) *http.Client {
				if !sslVerify {
					t.Error("sslVerify = false, want true")
				}
				return server.Client()
			}
			dependencies.now = func() time.Time { return currentTime }
			dependencies.sleep = func(duration time.Duration) { currentTime = currentTime.Add(duration) }
			dependencies.newProgress = func() deviceFlowProgress { return &testDeviceFlowProgress{} }

			token, err := authenticateDeviceFlow(
				server.URL+"/",
				"test-client",
				"openid profile",
				pkceMethod,
				true,
				false,
				dependencies,
			)
			if err != nil {
				t.Fatalf("AuthenticateDeviceFlow() error = %v", err)
			}
			if token != "test-access-token" {
				t.Errorf("token = %q, want test-access-token", token)
			}
			if got := tokenRequests.Load(); got != 2 {
				t.Errorf("token requests = %d, want 2", got)
			}
		})
	}
}

func TestGeneratePKCE(t *testing.T) {
	for _, tt := range []struct {
		name       string
		method     string
		wantMethod string
	}{
		{name: "default", wantMethod: PKCEMethodS256},
		{name: "S256", method: PKCEMethodS256, wantMethod: PKCEMethodS256},
		{name: "plain", method: PKCEMethodPlain, wantMethod: PKCEMethodPlain},
	} {
		t.Run(tt.name, func(t *testing.T) {
			verifier, challenge, method, err := GeneratePKCE(tt.method)
			if err != nil {
				t.Fatalf("GeneratePKCE() error = %v", err)
			}
			if method != tt.wantMethod {
				t.Errorf("method = %q, want %q", method, tt.wantMethod)
			}

			wantChallenge := verifier
			if method == PKCEMethodS256 {
				hash := sha256.Sum256([]byte(verifier))
				wantChallenge = base64.RawURLEncoding.EncodeToString(hash[:])
			}
			if challenge != wantChallenge {
				t.Errorf("challenge = %q, want %q", challenge, wantChallenge)
			}
		})
	}

	if _, _, _, err := GeneratePKCE("invalid"); err == nil {
		t.Error("GeneratePKCE() with invalid method expected an error")
	}
}

func TestReadOIDCResponseAndClose(t *testing.T) {
	tests := []struct {
		name        string
		reader      io.Reader
		missingBody bool
		wantBody    string
		wantContain string
	}{
		{
			name:     "valid response",
			reader:   strings.NewReader(`{"access_token":"test-token"}`),
			wantBody: `{"access_token":"test-token"}`,
		},
		{
			name:        "oversized response",
			reader:      strings.NewReader(strings.Repeat("x", maxOIDCResponseBodySize+1)),
			wantContain: "OIDC response body exceeds 65536-byte limit",
		},
		{
			name:        "read error",
			reader:      failingReader{err: errors.New("read failed")},
			wantContain: "read OIDC response body: read failed",
		},
		{
			name:        "missing response body",
			missingBody: true,
			wantContain: "OIDC response has no body",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body *trackingReadCloser
			response := &http.Response{}
			if !tt.missingBody {
				body = &trackingReadCloser{Reader: tt.reader}
				response.Body = body
			}

			got, err := readOIDCResponseAndClose(response)
			if string(got) != tt.wantBody {
				t.Errorf("readOIDCResponseAndClose() body = %q, want %q", got, tt.wantBody)
			}
			if tt.wantContain == "" && err != nil {
				t.Errorf("readOIDCResponseAndClose() error = %v", err)
			}
			if tt.wantContain != "" && (err == nil || !strings.Contains(err.Error(), tt.wantContain)) {
				t.Errorf("readOIDCResponseAndClose() error = %v, want containing %q", err, tt.wantContain)
			}
			if body != nil && !body.closed {
				t.Error("response body was not closed")
			}
		})
	}
}

type failingReader struct {
	err error
}

func (reader failingReader) Read([]byte) (int, error) {
	return 0, reader.err
}

type trackingReadCloser struct {
	io.Reader
	closed bool
}

func (body *trackingReadCloser) Close() error {
	body.closed = true
	return nil
}

func serverURL(r *http.Request) string {
	return "http://" + r.Host
}

// Test that the auth functions exist and have the correct signatures
func TestAuthFunctionsExist(t *testing.T) {
	// This test ensures the functions exist with correct signatures
	// without actually calling them to avoid network calls in CI/CD

	// Test that functions are callable (they exist)
	_ = AuthenticateDeviceFlow
	_ = AuthenticateDeviceFlowWithOutput
	_ = AuthenticateBrowserFlow
	_ = AuthenticateBrowserFlowWithOutput

	// If we reach here, both functions exist with expected signatures
	t.Log("Auth functions exist and have correct signatures")
}
