package ui

import (
	"strings"
	"testing"

	"github.com/fitbeard/radosgw-assume/internal/config"
)

func TestPrintUsage(t *testing.T) {
	// Test that PrintUsage doesn't panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("PrintUsage() panicked: %v", r)
		}
	}()
	
	PrintUsage()
}

func TestSelectProfileInteractively(t *testing.T) {
	// Test with empty profiles list
	_, err := SelectProfileInteractively([]string{})
	if err == nil {
		t.Error("SelectProfileInteractively() with empty slice should return error")
	}
	
	// Test error message content
	if !strings.Contains(err.Error(), "no profiles found") {
		t.Errorf("Error message should mention 'no profiles found', got: %s", err.Error())
	}
}

func TestPrintCredentials(t *testing.T) {
	// Test that PrintCredentials doesn't panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("PrintCredentials() panicked: %v", r)
		}
	}()
	
	result := &config.AssumeRoleResult{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQWLWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGdQrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz+scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA==",
		Expiration:      "2023-01-01T12:00:00Z",
		ProfileName:     "test-profile",
		EndpointURL:     "https://test.example.com",
	}
	
	PrintCredentials(result)
}

func TestPrintCredentialsOnly(t *testing.T) {
	// Test that PrintCredentialsOnly doesn't panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("PrintCredentialsOnly() panicked: %v", r)
		}
	}()
	
	result := &config.AssumeRoleResult{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "short-token",
		Expiration:      "2023-01-01T12:00:00Z",
		ProfileName:     "test",
		EndpointURL:     "https://test.example.com",
	}
	
	PrintCredentialsOnly(result)
}

func TestPrintCredentials_EnvProfile(t *testing.T) {
	// Test behavior when ProfileName is "env"
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("PrintCredentials() with env profile panicked: %v", r)
		}
	}()
	
	result := &config.AssumeRoleResult{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "env-token",
		Expiration:      "2023-01-01T12:00:00Z",
		ProfileName:     "env",
		EndpointURL:     "https://env.example.com",
	}
	
	PrintCredentials(result)
}

func TestPrintCredentialsOnly_EnvProfile(t *testing.T) {
	// Test behavior when ProfileName is "env"
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("PrintCredentialsOnly() with env profile panicked: %v", r)
		}
	}()
	
	result := &config.AssumeRoleResult{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "env-token",
		Expiration:      "2023-01-01T12:00:00Z",
		ProfileName:     "env",
		EndpointURL:     "https://env.example.com",
	}
	
	PrintCredentialsOnly(result)
}