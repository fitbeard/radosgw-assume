package sts

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/aws/smithy-go"

	"github.com/fitbeard/radosgw-assume/pkg/duration"
)

type userFacingError struct {
	message string
	cause   error
}

func (err *userFacingError) Error() string {
	return err.message
}

func (err *userFacingError) Unwrap() error {
	return err.cause
}

func newUserFacingError(cause error, format string, args ...any) error {
	return &userFacingError{
		message: fmt.Sprintf(format, args...),
		cause:   cause,
	}
}

func formatSTSError(err error, endpointURL, roleArn string, sessionDuration time.Duration) error {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := apiErr.ErrorCode()
		message := apiErr.ErrorMessage()

		switch code {
		case "AccessDenied":
			return newUserFacingError(err, "access denied: cannot assume role '%s' - "+
				"common causes: OIDC token expired, token claims don't match role trust policy, "+
				"or identity provider not authorized for this role", roleArn)
		case "InvalidIdentityToken":
			return newUserFacingError(err, "invalid identity token: the OIDC token is malformed or cannot be validated - "+
				"ensure the token is properly formatted and the OIDC provider is correctly configured in RadosGW")
		case "PackedPolicyTooLarge":
			return newUserFacingError(err, "policy too large: the session policy exceeds the maximum allowed size")
		case "MalformedPolicyDocument":
			return newUserFacingError(err, "malformed policy: the role '%s' has an invalid trust policy document", roleArn)
		case "IDPCommunicationError":
			return newUserFacingError(err, "IDP communication error: RadosGW could not communicate with the identity provider - "+
				"check network connectivity and OIDC provider URL configuration")
		case "InvalidArgument":
			return newUserFacingError(err, "invalid STS request for role '%s': RadosGW rejected one or more parameters - "+
				"requested session duration is %s; verify it does not exceed the role's max_session_duration", roleArn, duration.Format(sessionDuration))
		default:
			if message != "" {
				return newUserFacingError(err, "STS error [%s]: %s", code, message)
			}
			return newUserFacingError(err, "STS error [%s]: assume role failed for '%s'", code, roleArn)
		}
	}

	if networkError := formatSTSNetworkError(err, endpointURL); networkError != nil {
		return networkError
	}

	return fmt.Errorf("failed to assume role '%s' via endpoint '%s': %w", roleArn, endpointURL, err)
}

func formatSTSNetworkError(err error, endpointURL string) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return newUserFacingError(err, "connection timeout: STS endpoint '%s' did not respond in time - check network connectivity", endpointURL)
	}

	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return newUserFacingError(err, "connection timeout: STS endpoint '%s' did not respond in time - check network connectivity", endpointURL)
	}

	var dnsError *net.DNSError
	if errors.As(err, &dnsError) {
		return newUserFacingError(err, "unknown host: cannot resolve STS endpoint '%s' - check the endpoint URL for typos", endpointURL)
	}

	if errors.Is(err, syscall.ECONNREFUSED) {
		return newUserFacingError(err, "connection refused: cannot connect to STS endpoint '%s' - verify the endpoint URL is correct and the service is running", endpointURL)
	}

	if isCertificateVerificationError(err) {
		return newUserFacingError(err, "TLS certificate error: cannot verify certificate for '%s' - use radosgw_ssl_verify=false if using self-signed certificates", endpointURL)
	}

	return nil
}

func isCertificateVerificationError(err error) bool {
	var verificationError *tls.CertificateVerificationError
	if errors.As(err, &verificationError) {
		return true
	}

	var unknownAuthorityError x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthorityError) {
		return true
	}

	var hostnameError x509.HostnameError
	if errors.As(err, &hostnameError) {
		return true
	}

	var certificateInvalidError x509.CertificateInvalidError
	if errors.As(err, &certificateInvalidError) {
		return true
	}

	var systemRootsError x509.SystemRootsError
	return errors.As(err, &systemRootsError)
}
