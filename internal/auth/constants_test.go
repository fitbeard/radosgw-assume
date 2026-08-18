package auth

import "testing"

func TestConstants(t *testing.T) {
	// Verify constants have sensible values
	if AuthTimeout <= 0 {
		t.Errorf("AuthTimeout should be positive, got %v", AuthTimeout)
	}

	if OIDCRequestTimeout <= 0 {
		t.Errorf("OIDCRequestTimeout should be positive, got %v", OIDCRequestTimeout)
	}

	if ProgressInterval <= 0 {
		t.Errorf("ProgressInterval should be positive, got %v", ProgressInterval)
	}

	if DefaultPollingInterval <= 0 {
		t.Errorf("DefaultPollingInterval should be positive, got %d", DefaultPollingInterval)
	}

	if CallbackReadHeaderTimeout <= 0 {
		t.Errorf("CallbackReadHeaderTimeout should be positive, got %v", CallbackReadHeaderTimeout)
	}

	if CallbackShutdownTimeout <= 0 {
		t.Errorf("CallbackShutdownTimeout should be positive, got %v", CallbackShutdownTimeout)
	}

	if maxOIDCResponseBodySize <= 0 {
		t.Errorf("maxOIDCResponseBodySize should be positive, got %d", maxOIDCResponseBodySize)
	}

	if maxOIDCErrorDetailSize <= 0 || maxOIDCErrorDetailSize > maxOIDCResponseBodySize {
		t.Errorf("maxOIDCErrorDetailSize should be positive and bounded by the response limit, got %d", maxOIDCErrorDetailSize)
	}

	if CallbackPort <= 0 || CallbackPort > 65535 {
		t.Errorf("CallbackPort should be valid port number, got %d", CallbackPort)
	}

	if CallbackFallbackPort <= 0 || CallbackFallbackPort > 65535 {
		t.Errorf("CallbackFallbackPort should be valid port number, got %d", CallbackFallbackPort)
	}

	if CallbackPort == CallbackFallbackPort {
		t.Error("CallbackPort and CallbackFallbackPort should be different")
	}
}
