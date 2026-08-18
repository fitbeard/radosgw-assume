package auth

import "github.com/fitbeard/radosgw-assume/internal/config"

// OIDCOptions contains the shared configuration for an OIDC authentication
// flow. Context cancellation and user interaction output remain explicit at
// call sites because they describe execution rather than authentication data.
type OIDCOptions struct {
	ProviderURL string
	ClientID    string
	Scope       string
	PKCEMethod  config.PKCEMethod
	SSLVerify   bool
	Verbose     bool
}
