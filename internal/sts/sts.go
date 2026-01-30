package sts

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"github.com/fitbeard/radosgw-assume/internal/config"
)

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
	// Create STS client with anonymous credentials
	cfg := aws.Config{
		Credentials: aws.AnonymousCredentials{},
		Region: "us-east-1", // Required by AWS SDK, but not used by RadosGW
	}

	// Configure HTTP client for SSL verification
	if !sslVerify {
		cfg.HTTPClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
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

	result, err := stsClient.AssumeRoleWithWebIdentity(context.TODO(), input)
	if err != nil {
		return nil, formatSTSError(err, endpointURL, roleArn)
	}

	// Format expiration time
	expiration := result.Credentials.Expiration.Format(time.RFC3339)

	// Extract assumed role user ARN (contains session name)
	var assumedRoleArn string
	if result.AssumedRoleUser != nil && result.AssumedRoleUser.Arn != nil {
		assumedRoleArn = *result.AssumedRoleUser.Arn
	}

	return &config.AssumeRoleResult{
		AssumedRoleArn: assumedRoleArn,
		AccessKeyID:     *result.Credentials.AccessKeyId,
		SecretAccessKey: *result.Credentials.SecretAccessKey,
		SessionToken:    *result.Credentials.SessionToken,
		Expiration:      expiration,
		EndpointURL:     endpointURL,
	}, nil
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
			return fmt.Errorf("access denied: cannot assume role '%s' - "+
				"common causes: OIDC token expired, token claims don't match role trust policy, "+
				"or identity provider not authorized for this role", roleArn)
		case "InvalidIdentityToken":
			return fmt.Errorf("invalid identity token: the OIDC token is malformed or cannot be validated - "+
				"ensure the token is properly formatted and the OIDC provider is correctly configured in RadosGW")
		case "PackedPolicyTooLarge":
			return fmt.Errorf("policy too large: the session policy exceeds the maximum allowed size")
		case "MalformedPolicyDocument":
			return fmt.Errorf("malformed policy: the role '%s' has an invalid trust policy document", roleArn)
		case "IDPCommunicationError":
			return fmt.Errorf("IDP communication error: RadosGW could not communicate with the identity provider - "+
				"check network connectivity and OIDC provider URL configuration")
		default:
			// Include both code and message for unknown errors
			if message != "" {
				return fmt.Errorf("STS error [%s]: %s", code, message)
			}
			return fmt.Errorf("STS error [%s]: assume role failed for '%s'", code, roleArn)
		}
	}

	// Check for connection/network errors
	errStr := err.Error()
	if strings.Contains(errStr, "connection refused") {
		return fmt.Errorf("connection refused: cannot connect to STS endpoint '%s' - verify the endpoint URL is correct and the service is running", endpointURL)
	}
	if strings.Contains(errStr, "no such host") {
		return fmt.Errorf("unknown host: cannot resolve STS endpoint '%s' - check the endpoint URL for typos", endpointURL)
	}
	if strings.Contains(errStr, "certificate") || strings.Contains(errStr, "x509") {
		return fmt.Errorf("TLS certificate error: cannot verify certificate for '%s' - use radosgw_ssl_verify=false if using self-signed certificates", endpointURL)
	}
	if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline exceeded") {
		return fmt.Errorf("connection timeout: STS endpoint '%s' did not respond in time - check network connectivity", endpointURL)
	}

	// Fallback: wrap with context
	return fmt.Errorf("failed to assume role '%s' via endpoint '%s': %w", roleArn, endpointURL, err)
}
