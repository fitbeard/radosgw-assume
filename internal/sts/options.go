package sts

import "time"

// AssumeRoleOptions contains the inputs for an STS
// AssumeRoleWithWebIdentity request. WebIdentityToken is sensitive and must not
// be logged or included in user-facing diagnostics.
type AssumeRoleOptions struct {
	EndpointURL      string
	RoleARN          string
	WebIdentityToken string
	RoleSessionName  string
	SSLVerify        bool
	SessionDuration  time.Duration
}
