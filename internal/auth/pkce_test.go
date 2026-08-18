package auth

import (
	"bytes"
	"strings"
	"testing"
)

func TestGenerateRandomString(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{
			name:   "short string",
			length: 8,
		},
		{
			name:   "medium string",
			length: 32,
		},
		{
			name:   "long string",
			length: 96,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := GenerateRandomString(tt.length)
			if err != nil {
				t.Fatalf("GenerateRandomString returned error: %v", err)
			}

			if len(result) != tt.length {
				t.Errorf("GenerateRandomString length = %d, want %d", len(result), tt.length)
			}

			// Verify all characters are alphanumeric
			for i, c := range result {
				isLower := c >= 'a' && c <= 'z'
				isUpper := c >= 'A' && c <= 'Z'
				isDigit := c >= '0' && c <= '9'
				if !isLower && !isUpper && !isDigit {
					t.Errorf("GenerateRandomString contains invalid character at position %d: %c", i, c)
				}
			}
		})
	}
}

func TestGenerateRandomStringRejectsBiasedBytes(t *testing.T) {
	randomBytes := bytes.NewReader([]byte{0, 61, 248, 255, 62, 247})

	result, err := generateRandomString(4, randomBytes)
	if err != nil {
		t.Fatalf("generateRandomString() error = %v", err)
	}
	if result != "a9a9" {
		t.Errorf("generateRandomString() = %q, want %q", result, "a9a9")
	}
}

func TestGenerateRandomStringLengths(t *testing.T) {
	result, err := generateRandomString(0, strings.NewReader(""))
	if err != nil {
		t.Fatalf("generateRandomString(0) error = %v", err)
	}
	if result != "" {
		t.Errorf("generateRandomString(0) = %q, want empty", result)
	}

	_, err = generateRandomString(-1, strings.NewReader(""))
	if err == nil || !strings.Contains(err.Error(), "length cannot be negative") {
		t.Errorf("generateRandomString(-1) error = %v, want negative length error", err)
	}
}

func TestGenerateRandomStringReadError(t *testing.T) {
	_, err := generateRandomString(2, strings.NewReader("a"))
	if err == nil || !strings.Contains(err.Error(), "failed to generate random bytes") {
		t.Errorf("generateRandomString() error = %v, want wrapped read error", err)
	}
}

func TestGenerateRandomString_Uniqueness(t *testing.T) {
	// Generate multiple strings and verify they're different
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		s, err := GenerateRandomString(32)
		if err != nil {
			t.Fatalf("GenerateRandomString returned error: %v", err)
		}
		if seen[s] {
			t.Errorf("GenerateRandomString produced duplicate string: %s", s)
		}
		seen[s] = true
	}
}
