package auth

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSleepWithContext(t *testing.T) {
	if err := sleepWithContext(t.Context(), 0); err != nil {
		t.Errorf("sleepWithContext() completed wait error = %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if err := sleepWithContext(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Errorf("sleepWithContext() error = %v, want context cancellation", err)
	}
}

func TestDeviceResponseDuration(t *testing.T) {
	tests := []struct {
		name    string
		seconds int
		want    time.Duration
		wantErr string
		needs64 bool
	}{
		{name: "valid", seconds: 600, want: 10 * time.Minute},
		{name: "zero", wantErr: "must be a positive number"},
		{name: "negative", seconds: -1, wantErr: "must be a positive number"},
		{name: "overflow", seconds: int(^uint(0) >> 1), wantErr: "too large", needs64: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.needs64 && strconv.IntSize < 64 {
				t.Skip("time.Duration cannot overflow from an int-sized second count on 32-bit platforms")
			}
			result, err := deviceResponseDuration("expires_in", test.seconds)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Errorf("deviceResponseDuration() error = %v, want containing %q", err, test.wantErr)
				}
				return
			}
			if err != nil || result != test.want {
				t.Errorf("deviceResponseDuration() = (%v, %v), want (%v, nil)", result, err, test.want)
			}
		})
	}
}
