package sts

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"github.com/fitbeard/radosgw-assume/internal/config"
)

// STSRequestTimeout bounds the complete role-assumption operation, including retries.
const STSRequestTimeout = 30 * time.Second

// ValidateSessionName validates that the session name contains only alphanumeric
// characters and dashes, and doesn't start or end with a dash
func ValidateSessionName(name string) error {
	if name == "" {
		return fmt.Errorf("session name cannot be empty")
	}
	if strings.HasPrefix(name, "-") {
		return fmt.Errorf("session name cannot start with a dash")
	}
	if strings.HasSuffix(name, "-") {
		return fmt.Errorf("session name cannot end with a dash")
	}
	// Only allow alphanumeric and dashes
	validPattern := regexp.MustCompile(`^[a-zA-Z0-9-]+$`)
	if !validPattern.MatchString(name) {
		return fmt.Errorf("session name can only contain alphanumeric characters (a-z, A-Z, 0-9) and dashes (-)")
	}
	return nil
}

// AssumeRoleWithWebIdentity performs STS AssumeRoleWithWebIdentity operation
func AssumeRoleWithWebIdentity(endpointURL, roleArn, webIdentityToken, roleSessionName string, sslVerify bool, sessionDuration time.Duration) (*config.AssumeRoleResult, error) {
	return assumeRoleWithWebIdentity(endpointURL, roleArn, webIdentityToken, roleSessionName, sslVerify, sessionDuration, STSRequestTimeout)
}

func assumeRoleWithWebIdentity(endpointURL, roleArn, webIdentityToken, roleSessionName string, sslVerify bool, sessionDuration, requestTimeout time.Duration) (*config.AssumeRoleResult, error) {
	// Create STS client with anonymous credentials
	cfg := aws.Config{
		Credentials: aws.AnonymousCredentials{},
		HTTPClient:  newSTSHTTPClient(sslVerify, requestTimeout),
		Region:      "us-east-1", // Required by AWS SDK, but not used by RadosGW
	}

	stsClient := sts.NewFromConfig(cfg, func(o *sts.Options) {
		o.BaseEndpoint = aws.String(endpointURL)
	})

	// Assume role with web identity
	input := &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          aws.String(roleArn),
		RoleSessionName:  aws.String(roleSessionName),
		DurationSeconds:  aws.Int32(int32(sessionDuration.Seconds())),
		WebIdentityToken: aws.String(webIdentityToken),
	}

	requestContext, cancelRequest := context.WithTimeout(context.Background(), requestTimeout)
	defer cancelRequest()

	result, err := stsClient.AssumeRoleWithWebIdentity(requestContext, input)
	if err != nil {
		return nil, formatSTSError(err, endpointURL, roleArn)
	}

	return buildAssumeRoleResult(result, endpointURL)
}

func buildAssumeRoleResult(result *sts.AssumeRoleWithWebIdentityOutput, endpointURL string) (*config.AssumeRoleResult, error) {
	if result == nil {
		return nil, fmt.Errorf("STS endpoint '%s' returned an invalid response: response is missing", endpointURL)
	}
	if result.Credentials == nil {
		return nil, fmt.Errorf("STS endpoint '%s' returned an invalid response: credentials are missing", endpointURL)
	}

	credentials := result.Credentials
	var missingFields []string
	if aws.ToString(credentials.AccessKeyId) == "" {
		missingFields = append(missingFields, "AccessKeyId")
	}
	if aws.ToString(credentials.SecretAccessKey) == "" {
		missingFields = append(missingFields, "SecretAccessKey")
	}
	if aws.ToString(credentials.SessionToken) == "" {
		missingFields = append(missingFields, "SessionToken")
	}
	if credentials.Expiration == nil || credentials.Expiration.IsZero() {
		missingFields = append(missingFields, "Expiration")
	}
	if len(missingFields) > 0 {
		return nil, fmt.Errorf(
			"STS endpoint '%s' returned an invalid response: missing required credential fields: %s",
			endpointURL,
			strings.Join(missingFields, ", "),
		)
	}

	// Extract assumed role user ARN (contains session name)
	var assumedRoleArn string
	if result.AssumedRoleUser != nil && result.AssumedRoleUser.Arn != nil {
		assumedRoleArn = *result.AssumedRoleUser.Arn
	}

	return &config.AssumeRoleResult{
		AssumedRoleArn:  assumedRoleArn,
		AccessKeyID:     aws.ToString(credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(credentials.SecretAccessKey),
		SessionToken:    aws.ToString(credentials.SessionToken),
		Expiration:      credentials.Expiration.Format(time.RFC3339),
		EndpointURL:     endpointURL,
	}, nil
}

func newSTSHTTPClient(sslVerify bool, requestTimeout time.Duration) *http.Client {
	client := &http.Client{Timeout: requestTimeout}
	if !sslVerify {
		client.Transport = insecureDefaultTransport()
	}
	return client
}

func insecureDefaultTransport() *http.Transport {
	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		defaultTransport = &http.Transport{Proxy: http.ProxyFromEnvironment}
	}

	transport := defaultTransport.Clone()
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	}
	transport.TLSClientConfig.InsecureSkipVerify = true

	return transport
}

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

// formatSTSError converts AWS SDK errors into user-friendly error messages
func formatSTSError(err error, endpointURL, roleArn string) error {
	// Check for API errors from AWS SDK
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
		default:
			// Include both code and message for unknown errors
			if message != "" {
				return newUserFacingError(err, "STS error [%s]: %s", code, message)
			}
			return newUserFacingError(err, "STS error [%s]: assume role failed for '%s'", code, roleArn)
		}
	}

	if networkError := formatSTSNetworkError(err, endpointURL); networkError != nil {
		return networkError
	}

	// Fallback: wrap with context
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
