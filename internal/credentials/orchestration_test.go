package credentials

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/fitbeard/radosgw-assume/internal/auth"
	"github.com/fitbeard/radosgw-assume/internal/config"
	"github.com/fitbeard/radosgw-assume/internal/sts"

	"gopkg.in/ini.v1"
)

func TestGetCredentials_AuthFlows(t *testing.T) {
	tests := []struct {
		name               string
		authType           config.AuthType
		resolvedAuthType   config.AuthType
		wantVerboseMessage string
	}{
		{
			name:               "default device flow",
			resolvedAuthType:   config.AuthTypeDevice,
			wantVerboseMessage: "# Starting device authentication flow",
		},
		{
			name:               "browser flow",
			authType:           config.AuthTypeBrowser,
			resolvedAuthType:   config.AuthTypeBrowser,
			wantVerboseMessage: "# Starting browser authentication flow",
		},
		{
			name:               "token flow",
			authType:           config.AuthTypeToken,
			resolvedAuthType:   config.AuthTypeToken,
			wantVerboseMessage: "# Using pre-existing OIDC token",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stderr := &bytes.Buffer{}
			dependencies := newTestCredentialDependencies(t, stderr)
			expectedAccessToken := string(test.resolvedAuthType) + "-token"
			profileConfig := &config.ProfileConfig{
				EndpointURL:           "https://storage.example.com",
				RoleArn:               "arn:aws:iam::123456789012:role/TestRole",
				RadosGWOIDCProvider:   "https://oidc.example.com",
				RadosGWOIDCClientID:   "test-client",
				RadosGWOIDCAuthType:   test.authType,
				RadosGWOIDCScope:      "openid groups",
				RadosGWOIDCPKCEMethod: "plain",
				RadosGWSSLVerify:      "false",
			}

			switch test.resolvedAuthType {
			case config.AuthTypeDevice:
				dependencies.authenticateDevice = func(_ context.Context, options auth.OIDCOptions) (string, error) {
					assertAuthenticationOptions(t, options)
					return "device-token", nil
				}
			case config.AuthTypeBrowser:
				dependencies.authenticateBrowser = func(_ context.Context, options auth.OIDCOptions) (string, error) {
					assertAuthenticationOptions(t, options)
					return "browser-token", nil
				}
			case config.AuthTypeToken:
				expectedAccessToken = "environment-token"
				dependencies.getenv = func(name string) string {
					if name != "RADOSGW_OIDC_TOKEN" {
						t.Errorf("getenv() name = %q, want RADOSGW_OIDC_TOKEN", name)
					}
					return "environment-token"
				}
			}

			dependencies.assumeRole = func(_ context.Context, options sts.AssumeRoleOptions) (*config.AssumeRoleResult, error) {
				if options.EndpointURL != profileConfig.EndpointURL {
					t.Errorf("assumeRole() endpoint = %q, want %q", options.EndpointURL, profileConfig.EndpointURL)
				}
				if options.RoleARN != profileConfig.RoleArn {
					t.Errorf("assumeRole() role ARN = %q, want %q", options.RoleARN, profileConfig.RoleArn)
				}
				if options.WebIdentityToken != expectedAccessToken {
					t.Errorf("assumeRole() access token = %q, want %q", options.WebIdentityToken, expectedAccessToken)
				}
				if options.RoleSessionName != "radosgw-assume-20300102T030405Z" {
					t.Errorf("assumeRole() session name = %q, want deterministic default", options.RoleSessionName)
				}
				if options.SSLVerify {
					t.Error("assumeRole() SSL verification = true, want false")
				}
				if options.SessionDuration != 2*time.Hour {
					t.Errorf("assumeRole() duration = %v, want 2h", options.SessionDuration)
				}
				return &config.AssumeRoleResult{
					AssumedRoleArn: "arn:aws:sts::123456789012:assumed-role/TestRole/test-session",
					EndpointURL:    options.EndpointURL,
				}, nil
			}

			result, err := getCredentials(t.Context(), "test-profile", profileConfig, ini.Empty(), true, 2*time.Hour, dependencies)
			if err != nil {
				t.Fatalf("getCredentials() error = %v", err)
			}
			if result.ProfileName != "test-profile" {
				t.Errorf("ProfileName = %q, want test-profile", result.ProfileName)
			}

			verboseOutput := stderr.String()
			for _, expected := range []string{
				"# Direct role assumption: " + profileConfig.RoleArn,
				"# Using profile: test-profile",
				"# Auth type: " + string(test.resolvedAuthType),
				test.wantVerboseMessage,
				"# Session duration: 7200 seconds (2h)",
				"# Assumed role ARN:",
			} {
				if !strings.Contains(verboseOutput, expected) {
					t.Errorf("verbose output %q does not contain %q", verboseOutput, expected)
				}
			}
			if test.resolvedAuthType == config.AuthTypeToken && strings.Contains(verboseOutput, "# OIDC provider:") {
				t.Errorf("token verbose output unexpectedly contains OIDC provider: %q", verboseOutput)
			}
		})
	}
}

func TestGetCredentials_SourceProfile(t *testing.T) {
	stderr := &bytes.Buffer{}
	dependencies := newTestCredentialDependencies(t, stderr)
	awsConfig := ini.Empty()
	profileConfig := &config.ProfileConfig{
		RoleArn:         "arn:aws:iam::123456789012:role/DerivedRole",
		RoleSessionName: "custom-session",
		SourceProfile:   "base",
	}
	sourceConfig := &config.ProfileConfig{
		EndpointURL:         "https://storage.example.com",
		RadosGWOIDCAuthType: "token",
	}

	dependencies.resolveSourceProfile = func(gotProfile *config.ProfileConfig, gotConfig *ini.File, verboseMode bool) (*config.ProfileConfig, error) {
		if gotProfile != profileConfig || gotConfig != awsConfig || !verboseMode {
			t.Error("resolveSourceProfile() received unexpected arguments")
		}
		return sourceConfig, nil
	}
	dependencies.getenv = func(string) string { return "test-token" }
	dependencies.now = func() time.Time {
		t.Fatal("now() must not be called when a custom session name is configured")
		return time.Time{}
	}
	dependencies.assumeRole = func(_ context.Context, options sts.AssumeRoleOptions) (*config.AssumeRoleResult, error) {
		if options.EndpointURL != sourceConfig.EndpointURL || options.RoleARN != profileConfig.RoleArn || options.WebIdentityToken != "test-token" {
			t.Error("assumeRole() received unexpected role parameters")
		}
		if options.RoleSessionName != profileConfig.RoleSessionName {
			t.Errorf("assumeRole() session name = %q, want %q", options.RoleSessionName, profileConfig.RoleSessionName)
		}
		if !options.SSLVerify || options.SessionDuration != time.Hour {
			t.Error("assumeRole() received unexpected transport or duration settings")
		}
		return &config.AssumeRoleResult{}, nil
	}

	result, err := getCredentials(t.Context(), "derived", profileConfig, awsConfig, true, time.Hour, dependencies)
	if err != nil {
		t.Fatalf("getCredentials() error = %v", err)
	}
	if result.ProfileName != "derived" {
		t.Errorf("ProfileName = %q, want derived", result.ProfileName)
	}
	for _, expected := range []string{
		"# Role assumption: " + profileConfig.RoleArn,
		"# Source profile: base",
		"# Session name: custom-session",
	} {
		if !strings.Contains(stderr.String(), expected) {
			t.Errorf("verbose output %q does not contain %q", stderr.String(), expected)
		}
	}
}

func TestGetCredentials_DependencyErrors(t *testing.T) {
	tests := []struct {
		name        string
		authType    config.AuthType
		configure   func(*credentialDependencies)
		wantMessage string
	}{
		{
			name:     "missing token",
			authType: config.AuthTypeToken,
			configure: func(dependencies *credentialDependencies) {
				dependencies.getenv = func(string) string { return "" }
			},
			wantMessage: "RADOSGW_OIDC_TOKEN",
		},
		{
			name:     "device authentication",
			authType: config.AuthTypeDevice,
			configure: func(dependencies *credentialDependencies) {
				dependencies.authenticateDevice = func(context.Context, auth.OIDCOptions) (string, error) {
					return "", errors.New("device failure")
				}
			},
			wantMessage: "device authentication failed: device failure",
		},
		{
			name:     "browser authentication",
			authType: config.AuthTypeBrowser,
			configure: func(dependencies *credentialDependencies) {
				dependencies.authenticateBrowser = func(context.Context, auth.OIDCOptions) (string, error) {
					return "", errors.New("browser failure")
				}
			},
			wantMessage: "browser authentication failed: browser failure",
		},
		{
			name:     "role assumption",
			authType: config.AuthTypeToken,
			configure: func(dependencies *credentialDependencies) {
				dependencies.getenv = func(string) string { return "test-token" }
				dependencies.assumeRole = func(context.Context, sts.AssumeRoleOptions) (*config.AssumeRoleResult, error) {
					return nil, errors.New("STS failure")
				}
			},
			wantMessage: "STS failure",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dependencies := newTestCredentialDependencies(t, &bytes.Buffer{})
			profileConfig := &config.ProfileConfig{
				EndpointURL:         "https://storage.example.com",
				RoleArn:             "arn:aws:iam::123456789012:role/TestRole",
				RadosGWOIDCProvider: "https://oidc.example.com",
				RadosGWOIDCClientID: "test-client",
				RadosGWOIDCAuthType: test.authType,
			}
			test.configure(&dependencies)

			_, err := getCredentials(t.Context(), "test-profile", profileConfig, ini.Empty(), false, time.Hour, dependencies)
			if err == nil {
				t.Fatal("getCredentials() expected an error")
			}
			if !strings.Contains(err.Error(), test.wantMessage) {
				t.Errorf("getCredentials() error = %q, want it to contain %q", err, test.wantMessage)
			}
		})
	}
}

func TestGetCredentials_SourceProfileError(t *testing.T) {
	dependencies := newTestCredentialDependencies(t, &bytes.Buffer{})
	dependencies.resolveSourceProfile = func(*config.ProfileConfig, *ini.File, bool) (*config.ProfileConfig, error) {
		return nil, errors.New("source profile failure")
	}
	profileConfig := &config.ProfileConfig{
		RoleArn:       "arn:aws:iam::123456789012:role/TestRole",
		SourceProfile: "base",
	}

	_, err := getCredentials(t.Context(), "derived", profileConfig, ini.Empty(), false, time.Hour, dependencies)
	if err == nil || !strings.Contains(err.Error(), "source profile failure") {
		t.Errorf("getCredentials() error = %v, want source profile failure", err)
	}
}

func newTestCredentialDependencies(t *testing.T, stderr *bytes.Buffer) credentialDependencies {
	t.Helper()
	return credentialDependencies{
		stderr: stderr,
		getenv: func(string) string {
			t.Fatal("unexpected getenv() call")
			return ""
		},
		now: func() time.Time {
			return time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
		},
		resolveSourceProfile: func(*config.ProfileConfig, *ini.File, bool) (*config.ProfileConfig, error) {
			t.Fatal("unexpected resolveSourceProfile() call")
			return nil, nil
		},
		authenticateDevice: func(context.Context, auth.OIDCOptions) (string, error) {
			t.Fatal("unexpected authenticateDevice() call")
			return "", nil
		},
		authenticateBrowser: func(context.Context, auth.OIDCOptions) (string, error) {
			t.Fatal("unexpected authenticateBrowser() call")
			return "", nil
		},
		assumeRole: func(context.Context, sts.AssumeRoleOptions) (*config.AssumeRoleResult, error) {
			t.Fatal("unexpected assumeRole() call")
			return nil, nil
		},
	}
}

func assertAuthenticationOptions(t *testing.T, options auth.OIDCOptions) {
	t.Helper()
	if options.ProviderURL != "https://oidc.example.com" {
		t.Errorf("authenticate() provider URL = %q", options.ProviderURL)
	}
	if options.ClientID != "test-client" {
		t.Errorf("authenticate() client ID = %q", options.ClientID)
	}
	if options.Scope != "openid groups" {
		t.Errorf("authenticate() scope = %q", options.Scope)
	}
	if options.PKCEMethod != config.PKCEMethodPlain {
		t.Errorf("authenticate() PKCE method = %q", options.PKCEMethod)
	}
	if options.SSLVerify {
		t.Error("authenticate() SSL verification = true, want false")
	}
	if !options.Verbose {
		t.Error("authenticate() verbose mode = false, want true")
	}
}
