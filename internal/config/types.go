package config

// ProfileConfig represents the configuration for a RadosGW profile
type ProfileConfig struct {
	EndpointURL           string          `ini:"endpoint_url"`
	RadosGWOIDCProvider   string          `ini:"radosgw_oidc_provider"`
	RadosGWOIDCClientID   string          `ini:"radosgw_oidc_client_id"`
	RadosGWOIDCAuthType   AuthType        `ini:"radosgw_oidc_auth_type"`
	RadosGWOIDCScope      string          `ini:"radosgw_oidc_scope"`
	RadosGWOIDCPKCEMethod PKCEMethod      `ini:"radosgw_oidc_pkce_method"`
	RadosGWSSLVerify      SSLVerification `ini:"radosgw_ssl_verify"`
	RoleArn               string          `ini:"role_arn"`
	RoleSessionName       string          `ini:"role_session_name"`
	SourceProfile         string          `ini:"source_profile"`
}

// AssumeRoleResult contains the result of an STS AssumeRoleWithWebIdentity operation
type AssumeRoleResult struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      string
	ProfileName     string
	EndpointURL     string
	AssumedRoleArn  string
}
