package auth

import "time"

const (
	// AuthTimeout is the maximum time to wait for the browser callback.
	// Device authentication uses the provider-issued device code lifetime.
	AuthTimeout = 60 * time.Second
	// OIDCRequestTimeout bounds each request to the identity provider.
	OIDCRequestTimeout = 30 * time.Second
	// DefaultPollingInterval is the default interval for device flow polling.
	DefaultPollingInterval = 5
	// CallbackReadHeaderTimeout limits how long the local callback server waits for request headers.
	CallbackReadHeaderTimeout = 5 * time.Second
	// CallbackShutdownTimeout limits graceful shutdown of the local callback server.
	CallbackShutdownTimeout = 5 * time.Second
)

const (
	// CallbackPort is the primary port for the OAuth callback server.
	CallbackPort = 8080
	// CallbackFallbackPort is used if the primary port is busy.
	CallbackFallbackPort = 18088
)
