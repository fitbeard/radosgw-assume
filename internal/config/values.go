package config

// AuthType identifies an OIDC authentication flow.
type AuthType string

const (
	// AuthTypeDevice uses the OIDC device authorization flow.
	AuthTypeDevice AuthType = "device"
	// AuthTypeBrowser uses the browser authorization-code flow.
	AuthTypeBrowser AuthType = "browser"
	// AuthTypeToken uses an existing token from the environment.
	AuthTypeToken AuthType = "token"
)

// PKCEMethod identifies the proof-key transformation used by an OIDC flow.
type PKCEMethod string

const (
	// PKCEMethodS256 uses the base64url-encoded SHA-256 verifier digest.
	PKCEMethodS256 PKCEMethod = "S256"
	// PKCEMethodPlain sends the verifier as the challenge.
	PKCEMethodPlain PKCEMethod = "plain"
)

// SSLVerification stores the AWS configuration representation of TLS
// certificate verification behavior.
type SSLVerification string

const (
	sslVerificationFalse SSLVerification = "false"
	sslVerificationZero  SSLVerification = "0"
)

// Enabled reports whether TLS certificate verification should be enabled.
func (verification SSLVerification) Enabled() bool {
	return verification != sslVerificationFalse && verification != sslVerificationZero
}
