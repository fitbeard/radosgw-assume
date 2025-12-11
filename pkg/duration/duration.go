package duration

import (
	"fmt"
	"strconv"
	"time"
)

// Parse parses various duration formats and returns time.Duration
// Supports: "3600" (seconds), "60m" (minutes), "1h" (hours)
// Enforces minimum of 15 minutes (900 seconds) and maximum of 12 hours
func Parse(durationStr string) (time.Duration, error) {
	if durationStr == "" {
		return time.Hour, nil // Default 1 hour
	}

	// Try parsing as a Go duration first (e.g., "1h", "30m", "3600s")
	if duration, err := time.ParseDuration(durationStr); err == nil {
		return duration, nil
	}

	// Try parsing as seconds (e.g., "3600")
	if seconds, err := strconv.ParseInt(durationStr, 10, 64); err == nil {
		return time.Duration(seconds) * time.Second, nil
	}

	return 0, fmt.Errorf("invalid duration format: %s (use format like '1h', '30m', or '3600')", durationStr)
}

// Format formats time.Duration in human-readable format
func Format(d time.Duration) string {
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if hours > 0 {
		if minutes > 0 {
			return fmt.Sprintf("%dh %dm", hours, minutes)
		}
		return fmt.Sprintf("%dh", hours)
	} else if minutes > 0 {
		if seconds > 0 {
			return fmt.Sprintf("%dm %ds", minutes, seconds)
		}
		return fmt.Sprintf("%dm", minutes)
	}
	return fmt.Sprintf("%ds", seconds)
}

// Validate checks if duration is within acceptable limits (15m - 12h)
func Validate(d time.Duration) error {
	const minDuration = 15 * time.Minute
	const maxDuration = 12 * time.Hour

	if d < minDuration {
		return fmt.Errorf("duration cannot be less than 15 minutes (specified: %s)", Format(d))
	}
	if d > maxDuration {
		return fmt.Errorf("duration cannot exceed 12 hours (specified: %s)", Format(d))
	}
	return nil
}
