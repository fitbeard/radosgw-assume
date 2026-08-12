package ui

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/fitbeard/radosgw-assume/internal/config"

	"charm.land/huh/v2"
)

func TestShellQuote(t *testing.T) {
	tests := map[string]string{
		"":                    "''",
		"plain":               "'plain'",
		"profile with spaces": "'profile with spaces'",
		"$(touch unsafe)":     "'$(touch unsafe)'",
		"single'quote":        "'single'\"'\"'quote'",
	}

	for input, expected := range tests {
		t.Run(input, func(t *testing.T) {
			if result := shellQuote(input); result != expected {
				t.Errorf("shellQuote(%q) = %q, want %q", input, result, expected)
			}
		})
	}
}

func TestPrintUsage(t *testing.T) {
	// Test that PrintUsage doesn't panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("PrintUsage() panicked: %v", r)
		}
	}()

	PrintUsage()
}

func TestFprintUsageRequiresProfileFlag(t *testing.T) {
	var output bytes.Buffer
	FprintUsage(&output)

	for _, want := range []string{
		"Usage: radosgw-assume [OPTIONS]",
		"radosgw-assume exec [OPTIONS] -- COMMAND [ARG...]",
		"radosgw-assume shell [OPTIONS]",
		"-p, --profile PROFILE",
		"exec                      Run a command with temporary credentials",
		"shell                     Start an interactive shell with temporary credentials",
		"--no-prompt",
		"radosgw-assume exec -p myprofile -- aws s3 ls",
		"radosgw-assume shell -p myprofile",
		"radosgw-assume -p myprofile",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("FprintUsage() output missing %q", want)
		}
	}
	for _, unwanted := range []string{"[PROFILE]", "radosgw-assume myprofile"} {
		if strings.Contains(output.String(), unwanted) {
			t.Errorf("FprintUsage() output contains obsolete positional usage %q", unwanted)
		}
	}
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

func TestNormalizeSelectionError(t *testing.T) {
	if err := normalizeSelectionError(huh.ErrUserAborted); !errors.Is(err, ErrSelectionCancelled) {
		t.Errorf("normalizeSelectionError() = %v, want ErrSelectionCancelled", err)
	}

	want := errors.New("selection failure")
	if err := normalizeSelectionError(want); !errors.Is(err, want) {
		t.Errorf("normalizeSelectionError() = %v, want original error", err)
	}
}

func TestProfileSelectorCancellationKeys(t *testing.T) {
	keys := newProfileSelectorKeyMap().Quit.Keys()
	for _, want := range []string{"ctrl+c", "esc"} {
		if !slices.Contains(keys, want) {
			t.Errorf("selector quit keys = %v, want %q", keys, want)
		}
	}
}

func TestProfileSelectorHeight(t *testing.T) {
	tests := []struct {
		name         string
		profileCount int
		wantHeight   int
	}{
		{name: "one profile", profileCount: 1, wantHeight: 3},
		{name: "seven profiles", profileCount: 7, wantHeight: 9},
		{name: "ten profiles", profileCount: 10, wantHeight: 12},
		{name: "more than ten profiles", profileCount: 15, wantHeight: 12},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := profileSelectorHeight(test.profileCount); got != test.wantHeight {
				t.Errorf("profileSelectorHeight(%d) = %d, want %d", test.profileCount, got, test.wantHeight)
			}
		})
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

func TestFprintCredentialsUsesProfileFlag(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	result := &config.AssumeRoleResult{
		AccessKeyID:     "access-key",
		SecretAccessKey: "secret-key",
		SessionToken:    "session-token",
		Expiration:      "2030-01-01T00:00:00Z",
		ProfileName:     "profile with spaces",
		EndpointURL:     "https://storage.example.com",
	}

	FprintCredentials(&stdout, &stderr, result)
	if !strings.Contains(stderr.String(), "# Usage: eval $(radosgw-assume -p 'profile with spaces')") {
		t.Errorf("FprintCredentials() stderr = %q, want profile-flag usage hint", stderr.String())
	}
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
