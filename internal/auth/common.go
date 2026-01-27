package auth

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"time"
)

// Authentication timeouts and intervals
const (
	// AuthTimeout is the maximum time to wait for user authentication
	AuthTimeout = 60 * time.Second
	// ProgressInterval is how often to show progress indication
	ProgressInterval = 5 * time.Second
	// DefaultPollingInterval is the default interval for device flow polling
	DefaultPollingInterval = 5
	// ServerStartTimeout is how long to wait for the callback server to start
	ServerStartTimeout = 200 * time.Millisecond
)

// Callback server ports
const (
	// CallbackPort is the primary port for the OAuth callback server
	CallbackPort = 8080
	// CallbackFallbackPort is used if the primary port is busy
	CallbackFallbackPort = 18088
)

// NewHTTPClient creates an HTTP client with optional SSL verification
func NewHTTPClient(sslVerify bool) *http.Client {
	client := &http.Client{}
	if !sslVerify {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	return client
}

// ProgressIndicator manages progress indication during authentication
type ProgressIndicator struct {
	ticker *time.Ticker
	done   chan bool
}

// NewProgressIndicator creates and starts a new progress indicator
func NewProgressIndicator() *ProgressIndicator {
	p := &ProgressIndicator{
		ticker: time.NewTicker(ProgressInterval),
		done:   make(chan bool),
	}
	go p.run()
	return p
}

func (p *ProgressIndicator) run() {
	for {
		select {
		case <-p.ticker.C:
			fmt.Fprintf(os.Stderr, "#")
		case <-p.done:
			return
		}
	}
}

// Stop stops the progress indicator and prints a newline
func (p *ProgressIndicator) Stop() {
	p.ticker.Stop()
	p.done <- true
	fmt.Fprintf(os.Stderr, "\n")
}

// StopQuiet stops the progress indicator without printing a newline
func (p *ProgressIndicator) StopQuiet() {
	p.ticker.Stop()
	p.done <- true
}

// GenerateRandomString generates a cryptographically secure random string
func GenerateRandomString(length int) (string, error) {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)

	randomBytes := make([]byte, length)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	for i := 0; i < length; i++ {
		result[i] = chars[randomBytes[i]%byte(len(chars))]
	}

	return string(result), nil
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
