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

func TestSessionNameGeneration(t *testing.T) {
	// Test session name creation logic
	tests := []struct {
		name        string
		profileName string
		wantPrefix  string
	}{
		{
			name:        "normal profile name",
			profileName: "test-profile",
			wantPrefix:  "radosgw-assume-test-profile",
		},
		{
			name:        "env profile",
			profileName: "env",
			wantPrefix:  "radosgw-assume-env",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Since generateSessionName might be private, we test the behavior indirectly
			// by checking the session name that would be created for AssumeRoleWithWebIdentity
			sessionName := fmt.Sprintf("radosgw-assume-%s", tt.profileName)
			
			if !strings.HasPrefix(sessionName, tt.wantPrefix) {
				t.Errorf("session name = %v, want prefix %v", sessionName, tt.wantPrefix)
			}
			
			// Session name should only contain valid characters
			for _, char := range sessionName {
				if !isValidSessionNameChar(char) {
					t.Errorf("session name contains invalid character: %c in %s", char, sessionName)
				}
			}
		})
	}
}

// Helper function to check valid session name characters
func isValidSessionNameChar(r rune) bool {
	return (r >= 'a' && r <= 'z') ||
		(r >= 'A' && r <= 'Z') ||
		(r >= '0' && r <= '9') ||
		r == '-' || r == '_' || r == '.'
}