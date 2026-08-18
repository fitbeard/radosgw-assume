package credentialcache

import (
	"testing"
	"time"
)

func TestRefreshWindow(t *testing.T) {
	tests := []struct {
		duration time.Duration
		want     time.Duration
	}{
		{duration: 5 * time.Minute, want: time.Minute},
		{duration: 15 * time.Minute, want: 90 * time.Second},
		{duration: time.Hour, want: 6 * time.Minute},
		{duration: 12 * time.Hour, want: 15 * time.Minute},
	}
	for _, test := range tests {
		if got := refreshWindow(test.duration); got != test.want {
			t.Errorf("refreshWindow(%v) = %v, want %v", test.duration, got, test.want)
		}
	}
}
