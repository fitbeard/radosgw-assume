package config

import "fmt"

const (
	// DefaultOIDCScope is used when an authentication profile omits its scope.
	DefaultOIDCScope = "openid"
)

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

// Validate reports whether the authentication type is empty or supported.
// Empty values are valid because defaults are applied after profile inheritance.
func (authType AuthType) Validate() error {
	switch authType {
	case "", AuthTypeDevice, AuthTypeBrowser, AuthTypeToken:
		return nil
	default:
		return fmt.Errorf(
			"invalid radosgw_oidc_auth_type %q (supported: %s, %s, %s)",
			authType,
			AuthTypeDevice,
			AuthTypeBrowser,
			AuthTypeToken,
		)
	}
}

// PKCEMethod identifies the proof-key transformation used by an OIDC flow.
type PKCEMethod string

const (
	// PKCEMethodS256 uses the base64url-encoded SHA-256 verifier digest.
	PKCEMethodS256 PKCEMethod = "S256"
	// PKCEMethodPlain sends the verifier as the challenge.
	PKCEMethodPlain PKCEMethod = "plain"
)

// Validate reports whether the PKCE method is empty or supported.
// Empty values are valid because defaults are applied after profile inheritance.
func (method PKCEMethod) Validate() error {
	switch method {
	case "", PKCEMethodS256, PKCEMethodPlain:
		return nil
	default:
		return fmt.Errorf(
			"invalid radosgw_oidc_pkce_method %q (supported: %s, %s)",
			method,
			PKCEMethodS256,
			PKCEMethodPlain,
		)
	}
}

// SSLVerification stores the AWS configuration representation of TLS
// certificate verification behavior.
type SSLVerification string

const (
	// SSLVerificationTrue enables TLS certificate verification.
	SSLVerificationTrue SSLVerification = "true"
	// SSLVerificationFalse disables TLS certificate verification.
	SSLVerificationFalse SSLVerification = "false"
	// SSLVerificationOne is the numeric alias for enabled verification.
	SSLVerificationOne SSLVerification = "1"
	// SSLVerificationZero is the numeric alias for disabled verification.
	SSLVerificationZero SSLVerification = "0"
)

// Enabled reports whether TLS certificate verification should be enabled.
func (verification SSLVerification) Enabled() bool {
	return verification != SSLVerificationFalse && verification != SSLVerificationZero
}

// Validate reports whether the TLS certificate verification value is empty or
// one of the documented boolean representations.
func (verification SSLVerification) Validate() error {
	switch verification {
	case "", SSLVerificationTrue, SSLVerificationFalse, SSLVerificationOne, SSLVerificationZero:
		return nil
	default:
		return fmt.Errorf(
			"invalid radosgw_ssl_verify %q (supported: %s, %s, %s, %s)",
			verification,
			SSLVerificationTrue,
			SSLVerificationFalse,
			SSLVerificationOne,
			SSLVerificationZero,
		)
	}
}

// ValidateValues validates values that may be specified on either a complete
// profile or a partial profile participating in source_profile inheritance.
func (profileConfig *ProfileConfig) ValidateValues() error {
	if profileConfig == nil {
		return fmt.Errorf("profile configuration is missing")
	}
	if err := profileConfig.RadosGWOIDCAuthType.Validate(); err != nil {
		return err
	}
	if err := profileConfig.RadosGWOIDCPKCEMethod.Validate(); err != nil {
		return err
	}
	return profileConfig.RadosGWSSLVerify.Validate()
}

// Normalize returns a validated copy with defaults applied. Call it only after
// source_profile inheritance has been resolved so inherited values are retained.
func (profileConfig *ProfileConfig) Normalize() (*ProfileConfig, error) {
	if err := profileConfig.ValidateValues(); err != nil {
		return nil, err
	}

	normalized := *profileConfig
	if normalized.RadosGWOIDCAuthType == "" {
		normalized.RadosGWOIDCAuthType = AuthTypeDevice
	}
	if normalized.RadosGWOIDCAuthType != AuthTypeToken {
		if normalized.RadosGWOIDCScope == "" {
			normalized.RadosGWOIDCScope = DefaultOIDCScope
		}
		if normalized.RadosGWOIDCPKCEMethod == "" {
			normalized.RadosGWOIDCPKCEMethod = PKCEMethodS256
		}
	}
	if normalized.RadosGWSSLVerify == "" {
		normalized.RadosGWSSLVerify = SSLVerificationTrue
	}
	return &normalized, nil
}
