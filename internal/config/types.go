package config

// ProfileConfig represents the configuration for a RadosGW profile
type ProfileConfig struct {
	EndpointURL         string `ini:"endpoint_url"`
	RadosGWOIDCProvider string `ini:"radosgw_oidc_provider"`
	RadosGWOIDCClientID string `ini:"radosgw_oidc_client_id"`
	RadosGWOIDCAuthType string `ini:"radosgw_oidc_auth_type"`
	RadosGWOIDCToken    string `ini:"radosgw_oidc_token"`
	RadosGWOIDCScope    string `ini:"radosgw_oidc_scope"`
	RadosGWSSLVerify    string `ini:"radosgw_ssl_verify"`
	RoleArn             string `ini:"role_arn"`
	SourceProfile       string `ini:"source_profile"`
}

// AssumeRoleResult contains the result of an STS AssumeRoleWithWebIdentity operation
type AssumeRoleResult struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      string
	ProfileName     string
	EndpointURL     string
}
