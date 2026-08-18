package sts

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aws/smithy-go"
)

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
			name:        "invalid argument API error",
			err:         &smithy.GenericAPIError{Code: "InvalidArgument", Message: "UnknownError", Fault: smithy.FaultClient},
			wantContain: "requested session duration is 2h; verify it does not exceed the role's max_session_duration",
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
		{name: "connection refused", err: connectionRefusedError, wantContain: "connection refused"},
		{name: "no such host", err: dnsError, wantContain: "unknown host"},
		{name: "certificate error", err: certificateError, wantContain: "TLS certificate error"},
		{name: "network timeout error", err: timeoutError, wantContain: "connection timeout"},
		{
			name:        "context deadline error",
			err:         fmt.Errorf("wrapped request deadline: %w", context.DeadlineExceeded),
			wantContain: "connection timeout",
		},
		{name: "generic error", err: fmt.Errorf("some unknown error"), wantContain: roleArn},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := formatSTSError(test.err, endpointURL, roleArn, 2*time.Hour)
			if !strings.Contains(result.Error(), test.wantContain) {
				t.Errorf("formatSTSError() = %v, want to contain %v", result, test.wantContain)
			}
			if !errors.Is(result, test.err) {
				t.Errorf("formatSTSError() did not preserve original error %T", test.err)
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
			err := formatSTSError(cause, "https://s3.example.com", "arn:aws:iam:::role/TestRole", time.Hour)
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
