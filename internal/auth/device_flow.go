package auth

import (
	"context"
	"fmt"
	"net/url"
	"time"
)

func authenticateDeviceFlow(ctx context.Context, options OIDCOptions, dependencies deviceFlowDependencies) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	codeVerifier, codeChallenge, resolvedPKCEMethod, err := dependencies.generatePKCE(string(options.PKCEMethod))
	if err != nil {
		return "", err
	}
	client := dependencies.newHTTPClient(options.SSLVerify)
	endpoints, err := dependencies.discoverEndpoints(ctx, client, options.ProviderURL)
	if err != nil {
		return "", err
	}
	if err := endpoints.validateDeviceFlow(); err != nil {
		return "", err
	}

	if options.Verbose {
		_, _ = fmt.Fprintln(dependencies.stderr, "# Starting device authorization flow...")
	}

	authorizationData := url.Values{}
	authorizationData.Set("client_id", options.ClientID)
	authorizationData.Set("scope", options.Scope)
	authorizationData.Set("code_challenge", codeChallenge)
	authorizationData.Set("code_challenge_method", resolvedPKCEMethod)

	deviceResponse, err := requestDeviceAuthorization(ctx, client, endpoints.deviceAuthorization, authorizationData, options.ProviderURL)
	if err != nil {
		return "", err
	}
	deviceLifetime := time.Duration(deviceResponse.ExpiresIn) * time.Second

	printDeviceAuthenticationInstructions(dependencies.stderr, deviceResponse)

	tokenData := url.Values{}
	tokenData.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	tokenData.Set("client_id", options.ClientID)
	tokenData.Set("device_code", deviceResponse.DeviceCode)
	tokenData.Set("code_verifier", codeVerifier)

	pollInterval := time.Duration(deviceResponse.Interval) * time.Second
	if pollInterval == 0 {
		pollInterval = DefaultPollingInterval * time.Second
	}
	pollInterval = min(pollInterval, deviceLifetime)

	return pollDeviceToken(ctx, deviceTokenPoll{
		client:      client,
		endpoint:    endpoints.token,
		data:        tokenData,
		providerURL: options.ProviderURL,
		interval:    pollInterval,
		lifetime:    deviceLifetime,
		expiresAt:   dependencies.now().Add(deviceLifetime),
	}, options.Verbose, dependencies)
}
