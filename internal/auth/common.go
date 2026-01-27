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
