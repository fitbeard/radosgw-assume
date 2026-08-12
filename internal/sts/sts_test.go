package sts

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awssts "github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/aws/smithy-go"

	"github.com/fitbeard/radosgw-assume/internal/config"
	"github.com/fitbeard/radosgw-assume/pkg/duration"
)

func TestAssumeRoleWithWebIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm() error = %v", err)
		}
		if got := r.Form.Get("Action"); got != "AssumeRoleWithWebIdentity" {
			t.Errorf("Action = %q, want AssumeRoleWithWebIdentity", got)
		}
		if got := r.Form.Get("RoleArn"); got != "arn:aws:iam::123456789012:role/TestRole" {
			t.Errorf("RoleArn = %q, want test role ARN", got)
		}
		if got := r.Form.Get("WebIdentityToken"); got != "test-token" {
			t.Errorf("WebIdentityToken = %q, want test-token", got)
		}

		w.Header().Set("Content-Type", "text/xml")
		_, _ = fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?>
<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <AssumedRoleUser>
      <Arn>arn:aws:sts::123456789012:assumed-role/TestRole/test-session</Arn>
      <AssumedRoleId>AROATEST:test-session</AssumedRoleId>
    </AssumedRoleUser>
    <Credentials>
      <AccessKeyId>test-access-key</AccessKeyId>
      <SecretAccessKey>test-secret-key</SecretAccessKey>
      <SessionToken>test-session-token</SessionToken>
      <Expiration>2030-01-01T00:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
  <ResponseMetadata><RequestId>test-request-id</RequestId></ResponseMetadata>
</AssumeRoleWithWebIdentityResponse>`)
	}))
	t.Cleanup(server.Close)

	result, err := AssumeRoleWithWebIdentity(
		server.URL,
		"arn:aws:iam::123456789012:role/TestRole",
		"test-token",
		"test-session",
		true,
		time.Hour,
	)
	if err != nil {
		t.Fatalf("AssumeRoleWithWebIdentity() error = %v", err)
	}
	if result.AccessKeyID != "test-access-key" {
		t.Errorf("AccessKeyID = %q, want test-access-key", result.AccessKeyID)
	}
	if result.AssumedRoleArn != "arn:aws:sts::123456789012:assumed-role/TestRole/test-session" {
		t.Errorf("AssumedRoleArn = %q, want assumed role ARN", result.AssumedRoleArn)
	}
}

func TestAssumeRoleWithWebIdentityTimeout(t *testing.T) {
	releaseHandler := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		<-releaseHandler
	}))
	t.Cleanup(func() {
		close(releaseHandler)
		server.Close()
	})

	_, err := assumeRoleWithWebIdentity(
		server.URL,
		"arn:aws:iam::123456789012:role/TestRole",
		"test-token",
		"test-session",
		true,
		time.Hour,
		25*time.Millisecond,
	)
	if err == nil {
		t.Fatal("assumeRoleWithWebIdentity() expected a timeout error")
	}
	if !strings.Contains(err.Error(), "connection timeout") {
		t.Errorf("assumeRoleWithWebIdentity() error = %v, want connection timeout", err)
	}
}

func TestBuildAssumeRoleResultRejectsIncompleteCredentials(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(*awssts.AssumeRoleWithWebIdentityOutput) *awssts.AssumeRoleWithWebIdentityOutput
		wantContain string
	}{
		{
			name:        "missing response",
			mutate:      func(*awssts.AssumeRoleWithWebIdentityOutput) *awssts.AssumeRoleWithWebIdentityOutput { return nil },
			wantContain: "response is missing",
		},
		{
			name: "missing credentials",
			mutate: func(output *awssts.AssumeRoleWithWebIdentityOutput) *awssts.AssumeRoleWithWebIdentityOutput {
				output.Credentials = nil
				return output
			},
			wantContain: "credentials are missing",
		},
		{
			name: "missing access key ID",
			mutate: func(output *awssts.AssumeRoleWithWebIdentityOutput) *awssts.AssumeRoleWithWebIdentityOutput {
				output.Credentials.AccessKeyId = nil
				return output
			},
			wantContain: "AccessKeyId",
		},
		{
			name: "empty access key ID",
			mutate: func(output *awssts.AssumeRoleWithWebIdentityOutput) *awssts.AssumeRoleWithWebIdentityOutput {
				output.Credentials.AccessKeyId = aws.String("")
				return output
			},
			wantContain: "AccessKeyId",
		},
		{
			name: "missing secret access key",
			mutate: func(output *awssts.AssumeRoleWithWebIdentityOutput) *awssts.AssumeRoleWithWebIdentityOutput {
				output.Credentials.SecretAccessKey = nil
				return output
			},
			wantContain: "SecretAccessKey",
		},
		{
			name: "missing session token",
			mutate: func(output *awssts.AssumeRoleWithWebIdentityOutput) *awssts.AssumeRoleWithWebIdentityOutput {
				output.Credentials.SessionToken = nil
				return output
			},
			wantContain: "SessionToken",
		},
		{
			name: "missing expiration",
			mutate: func(output *awssts.AssumeRoleWithWebIdentityOutput) *awssts.AssumeRoleWithWebIdentityOutput {
				output.Credentials.Expiration = nil
				return output
			},
			wantContain: "Expiration",
		},
		{
			name: "zero expiration",
			mutate: func(output *awssts.AssumeRoleWithWebIdentityOutput) *awssts.AssumeRoleWithWebIdentityOutput {
				output.Credentials.Expiration = aws.Time(time.Time{})
				return output
			},
			wantContain: "Expiration",
		},
		{
			name: "multiple missing fields",
			mutate: func(output *awssts.AssumeRoleWithWebIdentityOutput) *awssts.AssumeRoleWithWebIdentityOutput {
				output.Credentials.AccessKeyId = nil
				output.Credentials.SessionToken = nil
				return output
			},
			wantContain: "AccessKeyId, SessionToken",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := buildAssumeRoleResult(test.mutate(completeAssumeRoleOutput()), "https://s3.example.com")
			if err == nil {
				t.Fatal("buildAssumeRoleResult() expected an error")
			}
			if result != nil {
				t.Errorf("buildAssumeRoleResult() result = %#v, want nil", result)
			}
			if !strings.Contains(err.Error(), test.wantContain) {
				t.Errorf("buildAssumeRoleResult() error = %v, want to contain %q", err, test.wantContain)
			}
			if !strings.Contains(err.Error(), "https://s3.example.com") {
				t.Errorf("buildAssumeRoleResult() error = %v, want endpoint context", err)
			}
		})
	}
}

func TestBuildAssumeRoleResultAllowsMissingAssumedRoleUser(t *testing.T) {
	output := completeAssumeRoleOutput()
	output.AssumedRoleUser = nil

	result, err := buildAssumeRoleResult(output, "https://s3.example.com")
	if err != nil {
		t.Fatalf("buildAssumeRoleResult() error = %v", err)
	}
	if result.AssumedRoleArn != "" {
		t.Errorf("AssumedRoleArn = %q, want empty", result.AssumedRoleArn)
	}
	if result.Expiration != "2030-01-01T00:00:00Z" {
		t.Errorf("Expiration = %q, want RFC3339 timestamp", result.Expiration)
	}
}

func completeAssumeRoleOutput() *awssts.AssumeRoleWithWebIdentityOutput {
	expiration := time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)
	return &awssts.AssumeRoleWithWebIdentityOutput{
		AssumedRoleUser: &types.AssumedRoleUser{
			Arn: aws.String("arn:aws:sts::123456789012:assumed-role/TestRole/test-session"),
		},
		Credentials: &types.Credentials{
			AccessKeyId:     aws.String("test-access-key"),
			SecretAccessKey: aws.String("test-secret-key"),
			SessionToken:    aws.String("test-session-token"),
			Expiration:      aws.Time(expiration),
		},
	}
}

func TestSTSRequestTimeout(t *testing.T) {
	if STSRequestTimeout <= 0 {
		t.Errorf("STSRequestTimeout should be positive, got %v", STSRequestTimeout)
	}
	if client := newSTSHTTPClient(true, STSRequestTimeout); client.Timeout != STSRequestTimeout {
		t.Errorf("STS HTTP client timeout = %v, want %v", client.Timeout, STSRequestTimeout)
	}
}

func TestSTSHTTPClientPreservesDefaultTransport(t *testing.T) {
	client := newSTSHTTPClient(false, STSRequestTimeout)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("STS HTTP client transport = %T, want *http.Transport", client.Transport)
	}
	if transport.TLSClientConfig == nil || !transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("STS HTTP client did not disable TLS verification")
	}

	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Skip("http.DefaultTransport is not an *http.Transport")
	}
	if transport == defaultTransport {
		t.Error("insecure transport must not mutate http.DefaultTransport")
	}
	if transport.Proxy == nil && defaultTransport.Proxy != nil {
		t.Error("insecure transport did not preserve proxy configuration")
	}
	if transport.ForceAttemptHTTP2 != defaultTransport.ForceAttemptHTTP2 {
		t.Errorf("ForceAttemptHTTP2 = %v, want %v", transport.ForceAttemptHTTP2, defaultTransport.ForceAttemptHTTP2)
	}
	if transport.MaxIdleConns != defaultTransport.MaxIdleConns {
		t.Errorf("MaxIdleConns = %d, want %d", transport.MaxIdleConns, defaultTransport.MaxIdleConns)
	}
	if transport.IdleConnTimeout != defaultTransport.IdleConnTimeout {
		t.Errorf("IdleConnTimeout = %v, want %v", transport.IdleConnTimeout, defaultTransport.IdleConnTimeout)
	}
	if transport.TLSHandshakeTimeout != defaultTransport.TLSHandshakeTimeout {
		t.Errorf("TLSHandshakeTimeout = %v, want %v", transport.TLSHandshakeTimeout, defaultTransport.TLSHandshakeTimeout)
	}
}

func TestValidateDuration(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		wantErr  bool
	}{
		{
			name:     "valid 1 hour",
			duration: time.Hour,
			wantErr:  false,
		},
		{
			name:     "valid 15 minutes (minimum)",
			duration: 15 * time.Minute,
			wantErr:  false,
		},
		{
			name:     "valid 12 hours (maximum)",
			duration: 12 * time.Hour,
			wantErr:  false,
		},
		{
			name:     "invalid too short",
			duration: 10 * time.Minute,
			wantErr:  true,
		},
		{
			name:     "invalid too long",
			duration: 13 * time.Hour,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use the duration package validation
			err := duration.Validate(tt.duration)

			if tt.wantErr && err == nil {
				t.Error("expected error but got none")
			}

			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestAssumeRoleResult(t *testing.T) {
	// Test the AssumeRoleResult struct creation
	result := &config.AssumeRoleResult{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "test-session-token",
		Expiration:      "2023-01-01T12:00:00Z",
		ProfileName:     "test-profile",
		EndpointURL:     "https://test.example.com",
	}

	if result.AccessKeyID != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("AssumeRoleResult.AccessKeyID = %s, want AKIAIOSFODNN7EXAMPLE", result.AccessKeyID)
	}

	if result.ProfileName != "test-profile" {
		t.Errorf("AssumeRoleResult.ProfileName = %s, want test-profile", result.ProfileName)
	}

	if result.EndpointURL != "https://test.example.com" {
		t.Errorf("AssumeRoleResult.EndpointURL = %s, want https://test.example.com", result.EndpointURL)
	}
}

func TestValidateSessionName(t *testing.T) {
	tests := []struct {
		name        string
		sessionName string
		wantErr     bool
		errContains string
	}{
		{
			name:        "valid simple name",
			sessionName: "my-session",
			wantErr:     false,
		},
		{
			name:        "valid alphanumeric",
			sessionName: "session123",
			wantErr:     false,
		},
		{
			name:        "valid with multiple dashes",
			sessionName: "my-custom-session-name",
			wantErr:     false,
		},
		{
			name:        "valid uppercase",
			sessionName: "MySession",
			wantErr:     false,
		},
		{
			name:        "valid mixed case with numbers",
			sessionName: "Session-123-Test",
			wantErr:     false,
		},
		{
			name:        "invalid empty",
			sessionName: "",
			wantErr:     true,
			errContains: "cannot be empty",
		},
		{
			name:        "invalid leading dash",
			sessionName: "-my-session",
			wantErr:     true,
			errContains: "cannot start with a dash",
		},
		{
			name:        "invalid trailing dash",
			sessionName: "my-session-",
			wantErr:     true,
			errContains: "cannot end with a dash",
		},
		{
			name:        "invalid underscore",
			sessionName: "my_session",
			wantErr:     true,
			errContains: "alphanumeric",
		},
		{
			name:        "invalid dot",
			sessionName: "my.session",
			wantErr:     true,
			errContains: "alphanumeric",
		},
		{
			name:        "invalid space",
			sessionName: "my session",
			wantErr:     true,
			errContains: "alphanumeric",
		},
		{
			name:        "invalid special characters",
			sessionName: "my@session!",
			wantErr:     true,
			errContains: "alphanumeric",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSessionName(tt.sessionName)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidateSessionName(%q) expected error but got none", tt.sessionName)
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ValidateSessionName(%q) error = %v, want to contain %q", tt.sessionName, err, tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateSessionName(%q) unexpected error: %v", tt.sessionName, err)
				}
			}
		})
	}
}

func TestDefaultSessionNameFormat(t *testing.T) {
	// Test that default session name follows expected format: radosgw-assume-TIMESTAMP
	// The timestamp format is 20060102T150405Z
	defaultPrefix := "radosgw-assume-"

	// Verify the prefix is correct
	if !strings.HasPrefix(defaultPrefix, "radosgw-assume-") {
		t.Errorf("default session name prefix should be 'radosgw-assume-', got %s", defaultPrefix)
	}

	// Verify that a timestamp-based session name would be valid
	exampleSessionName := "radosgw-assume-20240115T143052Z"
	err := ValidateSessionName(exampleSessionName)
	if err != nil {
		t.Errorf("ValidateSessionName(%q) should be valid for default timestamp format: %v", exampleSessionName, err)
	}
}

func TestFormatSTSError(t *testing.T) {
	endpointURL := "https://s3.example.com"
	roleArn := "arn:aws:iam:::role/TestRole"
	connectionRefusedError := &url.Error{
		Op:  "Post",
		URL: endpointURL,
		Err: &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED},
	}
	dnsError := &url.Error{
		Op:  "Post",
		URL: endpointURL,
		Err: &net.DNSError{Name: "bad.host", Err: "resolver failure", IsNotFound: true},
	}
	certificateError := &url.Error{
		Op:  "Post",
		URL: endpointURL,
		Err: &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}},
	}
	timeoutError := &url.Error{
		Op:  "Post",
		URL: endpointURL,
		Err: testTimeoutError{},
	}

	tests := []struct {
		name        string
		err         error
		wantContain string
	}{
		{
			name:        "access denied API error",
			err:         &smithy.GenericAPIError{Code: "AccessDenied", Message: "denied", Fault: smithy.FaultClient},
			wantContain: "access denied",
		},
		{
			name:        "invalid identity token API error",
			err:         &smithy.GenericAPIError{Code: "InvalidIdentityToken", Message: "invalid", Fault: smithy.FaultClient},
			wantContain: "invalid identity token",
		},
		{
			name:        "packed policy API error",
			err:         &smithy.GenericAPIError{Code: "PackedPolicyTooLarge", Message: "too large", Fault: smithy.FaultClient},
			wantContain: "policy too large",
		},
		{
			name:        "malformed policy API error",
			err:         &smithy.GenericAPIError{Code: "MalformedPolicyDocument", Message: "malformed", Fault: smithy.FaultClient},
			wantContain: "malformed policy",
		},
		{
			name:        "identity provider communication API error",
			err:         &smithy.GenericAPIError{Code: "IDPCommunicationError", Message: "unavailable", Fault: smithy.FaultServer},
			wantContain: "IDP communication error",
		},
		{
			name:        "unknown API error with message",
			err:         fmt.Errorf("wrapped: %w", &smithy.GenericAPIError{Code: "CustomError", Message: "custom message", Fault: smithy.FaultClient}),
			wantContain: "STS error [CustomError]: custom message",
		},
		{
			name:        "unknown API error without message",
			err:         &smithy.GenericAPIError{Code: "CustomError", Fault: smithy.FaultClient},
			wantContain: roleArn,
		},
		{
			name:        "connection refused",
			err:         connectionRefusedError,
			wantContain: "connection refused",
		},
		{
			name:        "no such host",
			err:         dnsError,
			wantContain: "unknown host",
		},
		{
			name:        "certificate error",
			err:         certificateError,
			wantContain: "TLS certificate error",
		},
		{
			name:        "network timeout error",
			err:         timeoutError,
			wantContain: "connection timeout",
		},
		{
			name:        "context deadline error",
			err:         fmt.Errorf("wrapped request deadline: %w", context.DeadlineExceeded),
			wantContain: "connection timeout",
		},
		{
			name:        "generic error",
			err:         fmt.Errorf("some unknown error"),
			wantContain: roleArn,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatSTSError(tt.err, endpointURL, roleArn)
			if !strings.Contains(result.Error(), tt.wantContain) {
				t.Errorf("formatSTSError() = %v, want to contain %v", result, tt.wantContain)
			}
			if !errors.Is(result, tt.err) {
				t.Errorf("formatSTSError() did not preserve original error %T", tt.err)
			}
		})
	}
}

func TestFormatSTSErrorDoesNotClassifyMessageText(t *testing.T) {
	for _, message := range []string{
		"connection refused",
		"no such host",
		"certificate validation failed",
		"request timeout",
		"deadline exceeded",
	} {
		t.Run(message, func(t *testing.T) {
			cause := errors.New(message)
			err := formatSTSError(cause, "https://s3.example.com", "arn:aws:iam:::role/TestRole")
			if !strings.HasPrefix(err.Error(), "failed to assume role") {
				t.Errorf("formatSTSError() classified untyped message %q: %v", message, err)
			}
			if !errors.Is(err, cause) {
				t.Error("formatSTSError() did not preserve original error")
			}
		})
	}
}

func TestCertificateVerificationErrorTypes(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "TLS verification", err: &tls.CertificateVerificationError{Err: errors.New("verify failed")}},
		{name: "unknown authority", err: x509.UnknownAuthorityError{}},
		{name: "hostname", err: x509.HostnameError{Host: "s3.example.com"}},
		{name: "invalid certificate", err: x509.CertificateInvalidError{}},
		{name: "system roots", err: x509.SystemRootsError{Err: errors.New("roots unavailable")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if !isCertificateVerificationError(fmt.Errorf("TLS handshake: %w", test.err)) {
				t.Errorf("isCertificateVerificationError() = false for %T", test.err)
			}
		})
	}

	if isCertificateVerificationError(errors.New("certificate text only")) {
		t.Error("isCertificateVerificationError() classified untyped message text")
	}
}

type testTimeoutError struct{}

func (testTimeoutError) Error() string {
	return "operation stalled"
}

func (testTimeoutError) Timeout() bool {
	return true
}
