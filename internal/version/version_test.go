package version

import (
	"strings"
	"testing"
)

func TestGetVersion(t *testing.T) {
	// This test checks the basic version getter
	version := GetVersion()
	if version == "" {
		t.Error("GetVersion() returned empty string")
	}
}

func TestGetFullVersion(t *testing.T) {
	// Test the full version string format
	fullVersion := GetFullVersion()
	if fullVersion == "" {
		t.Error("GetFullVersion() returned empty string")
	}
	
	// Check that it contains expected components
	if !strings.Contains(fullVersion, "version") {
		t.Error("GetFullVersion() should contain 'version'")
	}
	if !strings.Contains(fullVersion, "commit") {
		t.Error("GetFullVersion() should contain 'commit'")
	}
	if !strings.Contains(fullVersion, "built") {
		t.Error("GetFullVersion() should contain 'built'")
	}
}

func TestGetUserAgent(t *testing.T) {
	userAgent := GetUserAgent()
	if userAgent == "" {
		t.Error("GetUserAgent() returned empty string")
	}
	
	// Check that it contains expected components
	if !strings.Contains(userAgent, "radosgw-assume") {
		t.Error("GetUserAgent() should contain 'radosgw-assume'")
	}
	
	// Should contain version
	if !strings.Contains(userAgent, "/") {
		t.Error("GetUserAgent() should contain version separator")
	}
}

func TestPrintVersion(t *testing.T) {
	// This is mainly for coverage, hard to test output directly
	// We'll just ensure it doesn't panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("PrintVersion() panicked: %v", r)
		}
	}()
	
	PrintVersion()
}