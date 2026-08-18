package auth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

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

	endpoints, err := discoverOIDCEndpoints(t.Context(), client, issuer+"///")
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

func TestDiscoverOIDCEndpointsHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := discoverOIDCEndpoints(ctx, &http.Client{}, "https://oidc.example.com")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("discoverOIDCEndpoints() error = %v, want context cancellation", err)
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

			_, err := discoverOIDCEndpoints(t.Context(), client, test.providerURL)
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
