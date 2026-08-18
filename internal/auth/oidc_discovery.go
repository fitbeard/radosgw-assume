package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type oidcEndpoints struct {
	authorization       string
	deviceAuthorization string
	token               string
}

type oidcProviderMetadata struct {
	Issuer                      string `json:"issuer"`
	AuthorizationEndpoint       string `json:"authorization_endpoint"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	TokenEndpoint               string `json:"token_endpoint"`
}

func discoverOIDCEndpoints(ctx context.Context, client *http.Client, providerURL string) (oidcEndpoints, error) {
	issuer, issuerScheme, err := normalizeOIDCIssuer(providerURL)
	if err != nil {
		return oidcEndpoints{}, err
	}

	discoveryURL := issuer + "/.well-known/openid-configuration"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return oidcEndpoints{}, fmt.Errorf("failed to create OIDC discovery request: %w", err)
	}
	response, err := client.Do(request)
	if err != nil {
		return oidcEndpoints{}, fmt.Errorf("OIDC discovery request failed: %w", err)
	}
	body, err := readOIDCResponseAndClose(response)
	if err != nil {
		return oidcEndpoints{}, fmt.Errorf("failed to read OIDC discovery response: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		return oidcEndpoints{}, oidcHTTPStatusError("OIDC discovery", response.StatusCode, body, issuer)
	}

	var metadata oidcProviderMetadata
	if err := json.Unmarshal(body, &metadata); err != nil {
		return oidcEndpoints{}, fmt.Errorf("failed to parse OIDC discovery response: %w", err)
	}
	if metadata.Issuer != issuer {
		return oidcEndpoints{}, fmt.Errorf(
			"OIDC discovery issuer mismatch: configured %q, provider returned %q",
			issuer,
			metadata.Issuer,
		)
	}
	endpoints := oidcEndpoints{
		authorization:       metadata.AuthorizationEndpoint,
		deviceAuthorization: metadata.DeviceAuthorizationEndpoint,
		token:               metadata.TokenEndpoint,
	}
	for _, endpoint := range []struct {
		name string
		url  string
	}{
		{name: "authorization_endpoint", url: endpoints.authorization},
		{name: "device_authorization_endpoint", url: endpoints.deviceAuthorization},
		{name: "token_endpoint", url: endpoints.token},
	} {
		if endpoint.url == "" {
			continue
		}
		if err := validateOIDCEndpoint(endpoint.name, endpoint.url, issuerScheme); err != nil {
			return oidcEndpoints{}, err
		}
	}

	return endpoints, nil
}

func normalizeOIDCIssuer(providerURL string) (string, string, error) {
	issuer := strings.TrimRight(providerURL, "/")
	parsedIssuer, err := url.Parse(issuer)
	if err != nil {
		return "", "", fmt.Errorf("invalid OIDC provider URL %q: %w", providerURL, err)
	}
	if !parsedIssuer.IsAbs() || parsedIssuer.Host == "" {
		return "", "", fmt.Errorf("invalid OIDC provider URL %q: URL must be absolute", providerURL)
	}
	if parsedIssuer.Scheme != "https" && parsedIssuer.Scheme != "http" {
		return "", "", fmt.Errorf("invalid OIDC provider URL %q: scheme must be http or https", providerURL)
	}
	if parsedIssuer.User != nil {
		return "", "", fmt.Errorf("invalid OIDC provider URL %q: user information is not allowed", providerURL)
	}
	if parsedIssuer.RawQuery != "" || parsedIssuer.Fragment != "" {
		return "", "", fmt.Errorf("invalid OIDC provider URL %q: query and fragment are not allowed", providerURL)
	}

	return issuer, parsedIssuer.Scheme, nil
}

func validateOIDCEndpoint(name, endpointURL, issuerScheme string) error {
	parsedEndpoint, err := url.Parse(endpointURL)
	if err != nil {
		return fmt.Errorf("OIDC discovery returned invalid %s %q: %w", name, endpointURL, err)
	}
	if !parsedEndpoint.IsAbs() || parsedEndpoint.Host == "" {
		return fmt.Errorf("OIDC discovery returned invalid %s %q: URL must be absolute", name, endpointURL)
	}
	if parsedEndpoint.Scheme != "https" && parsedEndpoint.Scheme != "http" {
		return fmt.Errorf("OIDC discovery returned invalid %s %q: scheme must be http or https", name, endpointURL)
	}
	if issuerScheme == "https" && parsedEndpoint.Scheme != "https" {
		return fmt.Errorf("OIDC discovery returned invalid %s %q: HTTPS issuer endpoints must use https", name, endpointURL)
	}
	if parsedEndpoint.User != nil {
		return fmt.Errorf("OIDC discovery returned invalid %s %q: user information is not allowed", name, endpointURL)
	}
	if parsedEndpoint.Fragment != "" {
		return fmt.Errorf("OIDC discovery returned invalid %s %q: fragment is not allowed", name, endpointURL)
	}

	return nil
}

func (endpoints oidcEndpoints) validateBrowserFlow() error {
	if endpoints.authorization == "" {
		return fmt.Errorf("OIDC discovery response is missing authorization_endpoint required by browser authentication")
	}
	if endpoints.token == "" {
		return fmt.Errorf("OIDC discovery response is missing token_endpoint required by browser authentication")
	}

	return nil
}

func (endpoints oidcEndpoints) validateDeviceFlow() error {
	if endpoints.deviceAuthorization == "" {
		return fmt.Errorf("OIDC discovery response is missing device_authorization_endpoint required by device authentication")
	}
	if endpoints.token == "" {
		return fmt.Errorf("OIDC discovery response is missing token_endpoint required by device authentication")
	}

	return nil
}
