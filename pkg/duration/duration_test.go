package duration

import (
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected time.Duration
		wantErr  bool
	}{
		{
			name:     "empty string defaults to 1 hour",
			input:    "",
			expected: time.Hour,
			wantErr:  false,
		},
		{
			name:     "seconds as string",
			input:    "3600",
			expected: 3600 * time.Second,
			wantErr:  false,
		},
		{
			name:     "minutes format",
			input:    "30m",
			expected: 30 * time.Minute,
			wantErr:  false,
		},
		{
			name:     "hours format",
			input:    "2h",
			expected: 2 * time.Hour,
			wantErr:  false,
		},
		{
			name:     "seconds format",
			input:    "1800s",
			expected: 1800 * time.Second,
			wantErr:  false,
		},
		{
			name:     "complex duration",
			input:    "1h30m",
			expected: time.Hour + 30*time.Minute,
			wantErr:  false,
		},
		{
			name:    "invalid format",
			input:   "invalid",
			wantErr: true,
		},
		{
			name:    "negative duration",
			input:   "-30m",
			expected: -30 * time.Minute,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Parse(tt.input)
			
			if tt.wantErr {
				if err == nil {
					t.Errorf("Parse() expected error but got none")
				}
				return
			}
			
			if err != nil {
				t.Errorf("Parse() unexpected error: %v", err)
				return
			}
			
			if result != tt.expected {
				t.Errorf("Parse() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		wantErr  bool
	}{
		{
			name:     "valid 15 minutes",
			duration: 15 * time.Minute,
			wantErr:  false,
		},
		{
			name:     "valid 1 hour",
			duration: time.Hour,
			wantErr:  false,
		},
		{
			name:     "valid 12 hours",
			duration: 12 * time.Hour,
			wantErr:  false,
		},
		{
			name:     "too short - 14 minutes",
			duration: 14 * time.Minute,
			wantErr:  true,
		},
		{
			name:     "too long - 13 hours",
			duration: 13 * time.Hour,
			wantErr:  true,
		},
		{
			name:     "zero duration",
			duration: 0,
			wantErr:  true,
		},
		{
			name:     "negative duration",
			duration: -time.Hour,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.duration)
			
			if tt.wantErr && err == nil {
				t.Errorf("Validate() expected error but got none")
			}
			
			if !tt.wantErr && err != nil {
				t.Errorf("Validate() unexpected error: %v", err)
			}
		})
	}
}

func TestFormat(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		expected string
	}{
		{
			name:     "1 hour",
			duration: time.Hour,
			expected: "1h",
		},
		{
			name:     "30 minutes",
			duration: 30 * time.Minute,
			expected: "30m",
		},
		{
			name:     "90 minutes",
			duration: 90 * time.Minute,
			expected: "1h 30m",
		},
		{
			name:     "3600 seconds",
			duration: 3600 * time.Second,
			expected: "1h",
		},
		{
			name:     "1890 seconds",
			duration: 1890 * time.Second,
			expected: "31m 30s",
		},
		{
			name:     "2 hours 30 minutes 45 seconds",
			duration: 2*time.Hour + 30*time.Minute + 45*time.Second,
			expected: "2h 30m",
		},
		{
			name:     "45 seconds",
			duration: 45 * time.Second,
			expected: "45s",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Format(tt.duration)
			if result != tt.expected {
				t.Errorf("Format() = %v, want %v", result, tt.expected)
			}
		})
	}
}