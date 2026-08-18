package sts

import (
	"testing"
	"time"

	"github.com/fitbeard/radosgw-assume/internal/config"
	"github.com/fitbeard/radosgw-assume/pkg/duration"
)

func TestValidateDuration(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		wantErr  bool
	}{
		{name: "valid 1 hour", duration: time.Hour},
		{name: "valid 15 minutes (minimum)", duration: 15 * time.Minute},
		{name: "valid 12 hours (maximum)", duration: 12 * time.Hour},
		{name: "invalid too short", duration: 10 * time.Minute, wantErr: true},
		{name: "invalid too long", duration: 13 * time.Hour, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := duration.Validate(test.duration)
			if test.wantErr && err == nil {
				t.Error("expected error but got none")
			}
			if !test.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestAssumeRoleResult(t *testing.T) {
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
