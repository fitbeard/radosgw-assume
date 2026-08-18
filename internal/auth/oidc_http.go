package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/fitbeard/radosgw-assume/internal/httpclient"
)

const (
	// maxOIDCResponseBodySize prevents an identity provider from making the
	// client buffer an unbounded response body.
	maxOIDCResponseBodySize = 64 << 10
	// maxOIDCErrorDetailSize keeps provider errors useful without flooding the
	// terminal with an entire response body.
	maxOIDCErrorDetailSize = 1024
)

type oidcErrorResponse struct {
	Error     string `json:"error"`
	ErrorDesc string `json:"error_description"`
}

// NewHTTPClient creates a bounded HTTP client with optional SSL verification.
func NewHTTPClient(sslVerify bool) *http.Client {
	return httpclient.New(sslVerify, OIDCRequestTimeout)
}

func postOIDCForm(ctx context.Context, client *http.Client, endpoint string, data url.Values) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return client.Do(request)
}

func decodeOIDCTokenResponse(operation string, statusCode int, body []byte, providerURL string) (TokenResponse, error) {
	var tokenResponse TokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		if statusCode != http.StatusOK {
			return TokenResponse{}, oidcHTTPStatusError(operation, statusCode, body, providerURL)
		}
		return TokenResponse{}, fmt.Errorf("failed to parse token response: %w", err)
	}

	return tokenResponse, nil
}

func accessTokenFromOIDCResponse(tokenResponse TokenResponse, providerURL string) (string, error) {
	if tokenResponse.Error != "" {
		return "", FormatOIDCError(tokenResponse.Error, tokenResponse.ErrorDesc, providerURL)
	}
	if tokenResponse.AccessToken == "" {
		return "", fmt.Errorf("no access token received")
	}

	return tokenResponse.AccessToken, nil
}

func readOIDCResponseAndClose(response *http.Response) ([]byte, error) {
	if response.Body == nil {
		return nil, fmt.Errorf("OIDC response has no body")
	}
	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxOIDCResponseBodySize+1))
	if err != nil {
		return nil, fmt.Errorf("read OIDC response body: %w", err)
	}
	if len(body) > maxOIDCResponseBodySize {
		return nil, fmt.Errorf("OIDC response body exceeds %d-byte limit", maxOIDCResponseBodySize)
	}

	return body, nil
}

func oidcHTTPStatusError(operation string, statusCode int, body []byte, providerURL string) error {
	var errorResponse oidcErrorResponse
	if err := json.Unmarshal(body, &errorResponse); err == nil && errorResponse.Error != "" {
		return fmt.Errorf(
			"%s failed with status %d: %w",
			operation,
			statusCode,
			FormatOIDCError(
				errorResponse.Error,
				truncateOIDCErrorDetail(errorResponse.ErrorDesc),
				providerURL,
			),
		)
	}

	detail := truncateOIDCErrorDetail(strings.TrimSpace(string(body)))
	if detail == "" {
		detail = http.StatusText(statusCode)
	}
	if detail == "" {
		detail = "empty response body"
	}

	return fmt.Errorf("%s failed with status %d: %s", operation, statusCode, detail)
}

func truncateOIDCErrorDetail(detail string) string {
	runes := []rune(detail)
	if len(runes) <= maxOIDCErrorDetailSize {
		return detail
	}

	return string(runes[:maxOIDCErrorDetailSize]) + "…"
}

// FormatOIDCError translates OIDC error codes to user-friendly messages.
func FormatOIDCError(errorCode, errorDesc, providerURL string) error {
	switch errorCode {
	case "invalid_request":
		return fmt.Errorf("invalid request: the authentication request was malformed. %s", errorDesc)
	case "invalid_client":
		return fmt.Errorf("invalid client: the client ID is not recognized by the OIDC provider '%s'. Verify radosgw_oidc_client_id is correct", providerURL)
	case "invalid_grant":
		return fmt.Errorf("invalid grant: the authorization code or token is invalid or expired. Please try authenticating again")
	case "unauthorized_client":
		return fmt.Errorf("unauthorized client: this client is not authorized for the requested authentication flow. Check OIDC provider configuration")
	case "unsupported_grant_type":
		return fmt.Errorf("unsupported grant type: the OIDC provider does not support this authentication method. Verify the provider supports device flow or authorization code flow")
	case "invalid_scope":
		return fmt.Errorf("invalid scope: the requested scope '%s' is not valid. Check radosgw_oidc_scope configuration", errorDesc)
	case "access_denied":
		return fmt.Errorf("access denied: the user denied the authorization request or lacks permission")
	case "expired_token":
		return fmt.Errorf("token expired: the authorization code or device code has expired. Please start authentication again")
	case "server_error":
		return fmt.Errorf("server error: the OIDC provider encountered an internal error. Try again later or contact your administrator")
	case "temporarily_unavailable":
		return fmt.Errorf("temporarily unavailable: the OIDC provider is currently unavailable. Please try again later")
	default:
		if errorDesc != "" {
			return fmt.Errorf("authentication error [%s]: %s", errorCode, errorDesc)
		}
		return fmt.Errorf("authentication error [%s]: authentication failed", errorCode)
	}
}
