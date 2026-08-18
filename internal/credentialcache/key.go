package credentialcache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/fitbeard/radosgw-assume/internal/config"
)

const cacheKeyVersion = 1

type cacheKeyInput struct {
	Version           int                    `json:"version"`
	ProfileName       string                 `json:"profile_name"`
	EndpointURL       string                 `json:"endpoint_url"`
	OIDCProvider      string                 `json:"oidc_provider"`
	OIDCClientID      string                 `json:"oidc_client_id"`
	OIDCAuthType      config.AuthType        `json:"oidc_auth_type"`
	OIDCScope         string                 `json:"oidc_scope"`
	OIDCPKCEMethod    config.PKCEMethod      `json:"oidc_pkce_method"`
	SSLVerify         config.SSLVerification `json:"ssl_verify"`
	RoleARN           string                 `json:"role_arn"`
	RoleSessionName   string                 `json:"role_session_name"`
	SessionDuration   int64                  `json:"session_duration_nanoseconds"`
	OIDCTokenIdentity string                 `json:"oidc_token_identity,omitempty"`
}

// Key returns a stable, non-secret cache key for an effective profile.
func Key(profileName string, profileConfig *config.ProfileConfig, sessionDuration time.Duration, oidcToken string) (string, error) {
	if profileConfig == nil {
		return "", fmt.Errorf("create credential cache key: profile configuration is missing")
	}

	tokenIdentity := ""
	if profileConfig.RadosGWOIDCAuthType == config.AuthTypeToken {
		tokenHash := sha256.Sum256([]byte(oidcToken))
		tokenIdentity = hex.EncodeToString(tokenHash[:])
	}

	input := cacheKeyInput{
		Version:           cacheKeyVersion,
		ProfileName:       profileName,
		EndpointURL:       profileConfig.EndpointURL,
		OIDCProvider:      profileConfig.RadosGWOIDCProvider,
		OIDCClientID:      profileConfig.RadosGWOIDCClientID,
		OIDCAuthType:      profileConfig.RadosGWOIDCAuthType,
		OIDCScope:         profileConfig.RadosGWOIDCScope,
		OIDCPKCEMethod:    profileConfig.RadosGWOIDCPKCEMethod,
		SSLVerify:         profileConfig.RadosGWSSLVerify,
		RoleARN:           profileConfig.RoleArn,
		RoleSessionName:   profileConfig.RoleSessionName,
		SessionDuration:   int64(sessionDuration),
		OIDCTokenIdentity: tokenIdentity,
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		return "", fmt.Errorf("create credential cache key: %w", err)
	}

	keyHash := sha256.Sum256(encoded)
	return hex.EncodeToString(keyHash[:]), nil
}

func validateKey(key string) error {
	if len(key) != sha256.Size*2 {
		return fmt.Errorf("invalid credential cache key")
	}
	if _, err := hex.DecodeString(key); err != nil {
		return fmt.Errorf("invalid credential cache key: %w", err)
	}
	return nil
}
