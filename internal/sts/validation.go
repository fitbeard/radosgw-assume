package sts

import (
	"fmt"
	"regexp"
	"strings"
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
	validPattern := regexp.MustCompile(`^[a-zA-Z0-9-]+$`)
	if !validPattern.MatchString(name) {
		return fmt.Errorf("session name can only contain alphanumeric characters (a-z, A-Z, 0-9) and dashes (-)")
	}
	return nil
}
