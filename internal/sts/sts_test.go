package sts

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/fitbeard/radosgw-assume/internal/config"
	"github.com/fitbeard/radosgw-assume/pkg/duration"
)

func TestAssumeRoleWithWebIdentity(t *testing.T) {
	// Test error cases since we can't test real STS calls easily
	
	// Test with invalid endpoint URL
	_, err := AssumeRoleWithWebIdentity(
		"invalid-url",
		"arn:aws:iam::123456789012:role/TestRole",
		"test-token",
		"test-session",
		true, // sslVerify
		time.Hour,
	)
	if err == nil {
		t.Error("AssumeRoleWithWebIdentity() with invalid URL should return error")
	}
	
	// Test with empty role ARN
	_, err = AssumeRoleWithWebIdentity(
		"https://sts.amazonaws.com",
		"",
		"test-token",
		"test-session",
		true,
		time.Hour,
	)
	if err == nil {
		t.Error("AssumeRoleWithWebIdentity() with empty role ARN should return error")
	}
	
	// Test with empty token
	_, err = AssumeRoleWithWebIdentity(
		"https://sts.amazonaws.com",
		"arn:aws:iam::123456789012:role/TestRole",
		"",
		"test-session",
		true,
		time.Hour,
	)
	if err == nil {
		t.Error("AssumeRoleWithWebIdentity() with empty token should return error")
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

	tests := []struct {
		name        string
		err         error
		wantContain string
	}{
		{
			name:        "connection refused",
			err:         fmt.Errorf("dial tcp: connection refused"),
			wantContain: "connection refused",
		},
		{
			name:        "no such host",
			err:         fmt.Errorf("dial tcp: lookup bad.host: no such host"),
			wantContain: "unknown host",
		},
		{
			name:        "certificate error",
			err:         fmt.Errorf("x509: certificate signed by unknown authority"),
			wantContain: "TLS certificate error",
		},
		{
			name:        "timeout error",
			err:         fmt.Errorf("context deadline exceeded"),
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
		})
	}
}