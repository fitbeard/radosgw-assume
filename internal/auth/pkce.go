package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
)

const (
	// DefaultPKCEMethod is used when no PKCE method is configured.
	DefaultPKCEMethod = "S256"
	// PKCEMethodPlain sends the verifier as the challenge.
	PKCEMethodPlain = "plain"
	// PKCEMethodS256 sends the base64url-encoded SHA-256 verifier digest.
	PKCEMethodS256 = "S256"
)

// GenerateRandomString generates a cryptographically secure random string.
func GenerateRandomString(length int) (string, error) {
	return generateRandomString(length, rand.Reader)
}

func generateRandomString(length int, randomReader io.Reader) (string, error) {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const randomByteLimit = 256 - (256 % len(chars))

	if length < 0 {
		return "", fmt.Errorf("random string length cannot be negative: %d", length)
	}

	result := make([]byte, length)
	for generated := 0; generated < length; {
		candidates := result[generated:]
		if _, err := io.ReadFull(randomReader, candidates); err != nil {
			return "", fmt.Errorf("failed to generate random bytes: %w", err)
		}

		for _, candidate := range candidates {
			// 248 is the largest multiple of 62 that fits in one byte. Rejecting
			// the remaining values prevents modulo bias.
			if int(candidate) >= randomByteLimit {
				continue
			}
			result[generated] = chars[int(candidate)%len(chars)]
			generated++
		}
	}

	return string(result), nil
}

// GeneratePKCE creates a verifier and its matching challenge for the configured
// method. S256 is the secure default; plain must be selected explicitly.
func GeneratePKCE(method string) (verifier, challenge, resolvedMethod string, err error) {
	if method == "" {
		method = DefaultPKCEMethod
	}

	verifier, err = GenerateRandomString(96)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate code verifier: %w", err)
	}

	switch method {
	case PKCEMethodPlain:
		challenge = verifier
	case PKCEMethodS256:
		hash := sha256.Sum256([]byte(verifier))
		challenge = base64.RawURLEncoding.EncodeToString(hash[:])
	default:
		return "", "", "", fmt.Errorf("unsupported PKCE method %q (supported: %s, %s)", method, PKCEMethodS256, PKCEMethodPlain)
	}

	return verifier, challenge, method, nil
}
