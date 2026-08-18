package auth

import (
	"context"
	"fmt"
	"time"
)

func sleepWithContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()

	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func deviceResponseDuration(field string, seconds int) (time.Duration, error) {
	if seconds <= 0 {
		return 0, fmt.Errorf("invalid device authorization response: %s must be a positive number of seconds", field)
	}
	value := time.Duration(seconds)
	result := value * time.Second
	if result <= 0 || result/time.Second != value {
		return 0, fmt.Errorf("invalid device authorization response: %s is too large", field)
	}
	return result, nil
}
