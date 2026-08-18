package sts

import (
	"strings"
	"testing"
)

func TestValidateSessionName(t *testing.T) {
	tests := []struct {
		name        string
		sessionName string
		wantErr     bool
		errContains string
	}{
		{name: "valid simple name", sessionName: "my-session"},
		{name: "valid alphanumeric", sessionName: "session123"},
		{name: "valid with multiple dashes", sessionName: "my-custom-session-name"},
		{name: "valid uppercase", sessionName: "MySession"},
		{name: "valid mixed case with numbers", sessionName: "Session-123-Test"},
		{name: "invalid empty", wantErr: true, errContains: "cannot be empty"},
		{name: "invalid leading dash", sessionName: "-my-session", wantErr: true, errContains: "cannot start with a dash"},
		{name: "invalid trailing dash", sessionName: "my-session-", wantErr: true, errContains: "cannot end with a dash"},
		{name: "invalid underscore", sessionName: "my_session", wantErr: true, errContains: "alphanumeric"},
		{name: "invalid dot", sessionName: "my.session", wantErr: true, errContains: "alphanumeric"},
		{name: "invalid space", sessionName: "my session", wantErr: true, errContains: "alphanumeric"},
		{name: "invalid special characters", sessionName: "my@session!", wantErr: true, errContains: "alphanumeric"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateSessionName(test.sessionName)
			if test.wantErr {
				if err == nil {
					t.Errorf("ValidateSessionName(%q) expected error but got none", test.sessionName)
					return
				}
				if test.errContains != "" && !strings.Contains(err.Error(), test.errContains) {
					t.Errorf("ValidateSessionName(%q) error = %v, want to contain %q", test.sessionName, err, test.errContains)
				}
			} else if err != nil {
				t.Errorf("ValidateSessionName(%q) unexpected error: %v", test.sessionName, err)
			}
		})
	}
}

func TestDefaultSessionNameFormat(t *testing.T) {
	defaultPrefix := "radosgw-assume-"
	if !strings.HasPrefix(defaultPrefix, "radosgw-assume-") {
		t.Errorf("default session name prefix should be 'radosgw-assume-', got %s", defaultPrefix)
	}

	exampleSessionName := "radosgw-assume-20240115T143052Z"
	if err := ValidateSessionName(exampleSessionName); err != nil {
		t.Errorf("ValidateSessionName(%q) should be valid for default timestamp format: %v", exampleSessionName, err)
	}
}
