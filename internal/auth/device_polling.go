package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/fitbeard/radosgw-assume/pkg/duration"
)

type deviceTokenPoll struct {
	client      *http.Client
	endpoint    string
	data        url.Values
	providerURL string
	interval    time.Duration
	lifetime    time.Duration
	expiresAt   time.Time
}

func pollDeviceToken(ctx context.Context, poll deviceTokenPoll, verboseMode bool, dependencies deviceFlowDependencies) (string, error) {
	progress := dependencies.newProgress()

	for {
		remaining := poll.expiresAt.Sub(dependencies.now())
		if remaining <= 0 {
			break
		}
		wait := min(poll.interval, remaining)
		if err := dependencies.sleep(ctx, wait); err != nil {
			progress.StopQuiet()
			return "", err
		}
		if !dependencies.now().Before(poll.expiresAt) {
			break
		}

		response, err := postOIDCForm(ctx, poll.client, poll.endpoint, poll.data)
		if err != nil {
			progress.StopQuiet()
			return "", fmt.Errorf("token request failed: %w", err)
		}
		body, err := readOIDCResponseAndClose(response)
		if err != nil {
			progress.StopQuiet()
			return "", fmt.Errorf("failed to read token response: %w", err)
		}

		tokenResponse, err := decodeOIDCTokenResponse("token request", response.StatusCode, body, poll.providerURL)
		if err != nil {
			progress.StopQuiet()
			return "", err
		}

		switch response.StatusCode {
		case http.StatusOK:
			accessToken, err := accessTokenFromOIDCResponse(tokenResponse, poll.providerURL)
			if err != nil {
				progress.StopQuiet()
				return "", err
			}

			progress.Stop()
			if verboseMode {
				_, _ = fmt.Fprintln(dependencies.stderr, "# ✓ Authentication successful!")
			}
			return accessToken, nil
		case http.StatusBadRequest:
			switch tokenResponse.Error {
			case "authorization_pending":
				continue
			case "slow_down":
				slowDown := DefaultPollingInterval * time.Second
				if poll.lifetime-poll.interval < slowDown {
					poll.interval = poll.lifetime
				} else {
					poll.interval += slowDown
				}
				continue
			default:
				progress.StopQuiet()
				return "", oidcHTTPStatusError("token request", response.StatusCode, body, poll.providerURL)
			}
		default:
			progress.StopQuiet()
			return "", oidcHTTPStatusError("token request", response.StatusCode, body, poll.providerURL)
		}
	}

	progress.StopQuiet()
	return "", fmt.Errorf("device authorization expired after %s; start authentication again", duration.Format(poll.lifetime))
}
