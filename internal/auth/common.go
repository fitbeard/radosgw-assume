package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fitbeard/radosgw-assume/internal/httpclient"
)

// Authentication timeouts and intervals
const (
	// AuthTimeout is the maximum time to wait for user authentication
	AuthTimeout = 60 * time.Second
	// OIDCRequestTimeout bounds each request to the identity provider.
	OIDCRequestTimeout = 30 * time.Second
	// ProgressInterval is how often to show progress indication
	ProgressInterval = 5 * time.Second
	// DefaultPollingInterval is the default interval for device flow polling
	DefaultPollingInterval = 5
	// CallbackReadHeaderTimeout limits how long the local callback server waits for request headers.
	CallbackReadHeaderTimeout = 5 * time.Second
	// CallbackShutdownTimeout limits graceful shutdown of the local callback server.
	CallbackShutdownTimeout = 5 * time.Second
	// DefaultPKCEMethod is used when no PKCE method is configured.
	DefaultPKCEMethod = "S256"
	// PKCEMethodPlain sends the verifier as the challenge.
	PKCEMethodPlain = "plain"
	// PKCEMethodS256 sends the base64url-encoded SHA-256 verifier digest.
	PKCEMethodS256 = "S256"
	// maxOIDCResponseBodySize prevents an identity provider from making the
	// client buffer an unbounded response body.
	maxOIDCResponseBodySize = 64 << 10
	// maxOIDCErrorDetailSize keeps provider errors useful without flooding the
	// terminal with an entire response body.
	maxOIDCErrorDetailSize = 1024
)

// Callback server ports
const (
	// CallbackPort is the primary port for the OAuth callback server
	CallbackPort = 8080
	// CallbackFallbackPort is used if the primary port is busy
	CallbackFallbackPort = 18088
)

// NewHTTPClient creates a bounded HTTP client with optional SSL verification.
func NewHTTPClient(sslVerify bool) *http.Client {
	return httpclient.New(sslVerify, OIDCRequestTimeout)
}

type oidcErrorResponse struct {
	Error     string `json:"error"`
	ErrorDesc string `json:"error_description"`
}

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

func discoverOIDCEndpoints(client *http.Client, providerURL string) (oidcEndpoints, error) {
	issuer, issuerScheme, err := normalizeOIDCIssuer(providerURL)
	if err != nil {
		return oidcEndpoints{}, err
	}

	discoveryURL := issuer + "/.well-known/openid-configuration"
	response, err := client.Get(discoveryURL)
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

func decodeOIDCTokenResponse(operation string, statusCode int, body []byte, providerURL string) (TokenResponse, error) {
	var tokenResponse TokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		if statusCode != http.StatusOK {
			return TokenResponse{}, oidcHTTPStatusError(operation, statusCode, body, providerURL)
		}
		return TokenResponse{}, fmt.Errorf("failed to parse token response: %w", err)
	}

	return tokenResponse, nil
}

func accessTokenFromOIDCResponse(tokenResponse TokenResponse, providerURL string) (string, error) {
	if tokenResponse.Error != "" {
		return "", FormatOIDCError(tokenResponse.Error, tokenResponse.ErrorDesc, providerURL)
	}
	if tokenResponse.AccessToken == "" {
		return "", fmt.Errorf("no access token received")
	}

	return tokenResponse.AccessToken, nil
}

func readOIDCResponseAndClose(response *http.Response) ([]byte, error) {
	if response.Body == nil {
		return nil, fmt.Errorf("OIDC response has no body")
	}
	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxOIDCResponseBodySize+1))
	if err != nil {
		return nil, fmt.Errorf("read OIDC response body: %w", err)
	}
	if len(body) > maxOIDCResponseBodySize {
		return nil, fmt.Errorf("OIDC response body exceeds %d-byte limit", maxOIDCResponseBodySize)
	}

	return body, nil
}

func oidcHTTPStatusError(operation string, statusCode int, body []byte, providerURL string) error {
	var errorResponse oidcErrorResponse
	if err := json.Unmarshal(body, &errorResponse); err == nil && errorResponse.Error != "" {
		return fmt.Errorf(
			"%s failed with status %d: %w",
			operation,
			statusCode,
			FormatOIDCError(
				errorResponse.Error,
				truncateOIDCErrorDetail(errorResponse.ErrorDesc),
				providerURL,
			),
		)
	}

	detail := truncateOIDCErrorDetail(strings.TrimSpace(string(body)))
	if detail == "" {
		detail = http.StatusText(statusCode)
	}
	if detail == "" {
		detail = "empty response body"
	}

	return fmt.Errorf("%s failed with status %d: %s", operation, statusCode, detail)
}

func truncateOIDCErrorDetail(detail string) string {
	runes := []rune(detail)
	if len(runes) <= maxOIDCErrorDetailSize {
		return detail
	}

	return string(runes[:maxOIDCErrorDetailSize]) + "…"
}

// ProgressIndicator manages progress indication during authentication.
type ProgressIndicator struct {
	output     io.Writer
	ticks      <-chan time.Time
	stopTicker func()
	done       chan struct{}
	stopped    chan struct{}
	stopOnce   sync.Once
}

// NewProgressIndicator creates and starts a new progress indicator.
func NewProgressIndicator() *ProgressIndicator {
	ticker := time.NewTicker(ProgressInterval)
	return newProgressIndicator(os.Stderr, ticker.C, ticker.Stop)
}

func newProgressIndicator(output io.Writer, ticks <-chan time.Time, stopTicker func()) *ProgressIndicator {
	progress := &ProgressIndicator{
		output:     output,
		ticks:      ticks,
		stopTicker: stopTicker,
		done:       make(chan struct{}),
		stopped:    make(chan struct{}),
	}
	go progress.run()
	return progress
}

func (p *ProgressIndicator) run() {
	defer close(p.stopped)
	for {
		select {
		case <-p.ticks:
			_, _ = fmt.Fprint(p.output, "#")
		case <-p.done:
			return
		}
	}
}

// Stop stops the progress indicator and prints a newline.
func (p *ProgressIndicator) Stop() {
	p.stop(true)
}

// StopQuiet stops the progress indicator without printing a newline.
func (p *ProgressIndicator) StopQuiet() {
	p.stop(false)
}

func (p *ProgressIndicator) stop(printNewline bool) {
	p.stopOnce.Do(func() {
		p.stopTicker()
		close(p.done)
		<-p.stopped
		if printNewline {
			_, _ = fmt.Fprintln(p.output)
		}
	})
}

// GenerateRandomString generates a cryptographically secure random string.
func GenerateRandomString(length int) (string, error) {
	return generateRandomString(length, rand.Reader)
}

func generateRandomString(length int, randomReader io.Reader) (string, error) {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const randomByteLimit = 256 - (256 % len(chars))

	if length < 0 {
		return "", fmt.Errorf("random string length cannot be negative: %d", length)
	}

	result := make([]byte, length)
	for generated := 0; generated < length; {
		candidates := result[generated:]
		if _, err := io.ReadFull(randomReader, candidates); err != nil {
			return "", fmt.Errorf("failed to generate random bytes: %w", err)
		}

		for _, candidate := range candidates {
			// 248 is the largest multiple of 62 that fits in one byte. Rejecting
			// the remaining values prevents modulo bias.
			if int(candidate) >= randomByteLimit {
				continue
			}
			result[generated] = chars[int(candidate)%len(chars)]
			generated++
		}
	}

	return string(result), nil
}

// GeneratePKCE creates a verifier and its matching challenge for the configured
// method. S256 is the secure default; plain must be selected explicitly.
func GeneratePKCE(method string) (verifier, challenge, resolvedMethod string, err error) {
	if method == "" {
		method = DefaultPKCEMethod
	}

	verifier, err = GenerateRandomString(96)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate code verifier: %w", err)
	}

	switch method {
	case PKCEMethodPlain:
		challenge = verifier
	case PKCEMethodS256:
		hash := sha256.Sum256([]byte(verifier))
		challenge = base64.RawURLEncoding.EncodeToString(hash[:])
	default:
		return "", "", "", fmt.Errorf("unsupported PKCE method %q (supported: %s, %s)", method, PKCEMethodS256, PKCEMethodPlain)
	}

	return verifier, challenge, method, nil
}

// FormatOIDCError translates OIDC error codes to user-friendly messages
func FormatOIDCError(errorCode, errorDesc, providerURL string) error {
	switch errorCode {
	case "invalid_request":
		return fmt.Errorf("invalid request: the authentication request was malformed. %s", errorDesc)
	case "invalid_client":
		return fmt.Errorf("invalid client: the client ID is not recognized by the OIDC provider '%s'. Verify radosgw_oidc_client_id is correct", providerURL)
	case "invalid_grant":
		return fmt.Errorf("invalid grant: the authorization code or token is invalid or expired. Please try authenticating again")
	case "unauthorized_client":
		return fmt.Errorf("unauthorized client: this client is not authorized for the requested authentication flow. Check OIDC provider configuration")
	case "unsupported_grant_type":
		return fmt.Errorf("unsupported grant type: the OIDC provider does not support this authentication method. Verify the provider supports device flow or authorization code flow")
	case "invalid_scope":
		return fmt.Errorf("invalid scope: the requested scope '%s' is not valid. Check radosgw_oidc_scope configuration", errorDesc)
	case "access_denied":
		return fmt.Errorf("access denied: the user denied the authorization request or lacks permission")
	case "expired_token":
		return fmt.Errorf("token expired: the authorization code or device code has expired. Please start authentication again")
	case "server_error":
		return fmt.Errorf("server error: the OIDC provider encountered an internal error. Try again later or contact your administrator")
	case "temporarily_unavailable":
		return fmt.Errorf("temporarily unavailable: the OIDC provider is currently unavailable. Please try again later")
	default:
		if errorDesc != "" {
			return fmt.Errorf("authentication error [%s]: %s", errorCode, errorDesc)
		}
		return fmt.Errorf("authentication error [%s]: authentication failed", errorCode)
	}
}
