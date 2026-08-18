package sts

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAssumeRoleWithWebIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm() error = %v", err)
		}
		if got := r.Form.Get("Action"); got != "AssumeRoleWithWebIdentity" {
			t.Errorf("Action = %q, want AssumeRoleWithWebIdentity", got)
		}
		if got := r.Form.Get("RoleArn"); got != "arn:aws:iam::123456789012:role/TestRole" {
			t.Errorf("RoleArn = %q, want test role ARN", got)
		}
		if got := r.Form.Get("WebIdentityToken"); got != "test-token" {
			t.Errorf("WebIdentityToken = %q, want test-token", got)
		}
		if got := r.Form.Get("DurationSeconds"); got != "3600" {
			t.Errorf("DurationSeconds = %q, want 3600", got)
		}

		w.Header().Set("Content-Type", "text/xml")
		_, _ = fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?>
<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <AssumedRoleUser>
      <Arn>arn:aws:sts::123456789012:assumed-role/TestRole/test-session</Arn>
      <AssumedRoleId>AROATEST:test-session</AssumedRoleId>
    </AssumedRoleUser>
    <Credentials>
      <AccessKeyId>test-access-key</AccessKeyId>
      <SecretAccessKey>test-secret-key</SecretAccessKey>
      <SessionToken>test-session-token</SessionToken>
      <Expiration>2030-01-01T00:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
  <ResponseMetadata><RequestId>test-request-id</RequestId></ResponseMetadata>
</AssumeRoleWithWebIdentityResponse>`)
	}))
	t.Cleanup(server.Close)

	result, err := AssumeRoleWithWebIdentity(
		t.Context(),
		AssumeRoleOptions{
			EndpointURL:      server.URL,
			RoleARN:          "arn:aws:iam::123456789012:role/TestRole",
			WebIdentityToken: "test-token",
			RoleSessionName:  "test-session",
			SSLVerify:        true,
			SessionDuration:  time.Hour,
		},
	)
	if err != nil {
		t.Fatalf("AssumeRoleWithWebIdentity() error = %v", err)
	}
	if result.AccessKeyID != "test-access-key" {
		t.Errorf("AccessKeyID = %q, want test-access-key", result.AccessKeyID)
	}
	if result.AssumedRoleArn != "arn:aws:sts::123456789012:assumed-role/TestRole/test-session" {
		t.Errorf("AssumedRoleArn = %q, want assumed role ARN", result.AssumedRoleArn)
	}
}

func TestAssumeRoleWithWebIdentityTimeout(t *testing.T) {
	releaseHandler := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		<-releaseHandler
	}))
	t.Cleanup(func() {
		close(releaseHandler)
		server.Close()
	})

	_, err := assumeRoleWithWebIdentity(
		t.Context(),
		AssumeRoleOptions{
			EndpointURL:      server.URL,
			RoleARN:          "arn:aws:iam::123456789012:role/TestRole",
			WebIdentityToken: "test-token",
			RoleSessionName:  "test-session",
			SSLVerify:        true,
			SessionDuration:  time.Hour,
		},
		25*time.Millisecond,
	)
	if err == nil {
		t.Fatal("assumeRoleWithWebIdentity() expected a timeout error")
	}
	if !strings.Contains(err.Error(), "connection timeout") {
		t.Errorf("assumeRoleWithWebIdentity() error = %v, want connection timeout", err)
	}
}

func TestAssumeRoleWithWebIdentityHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := AssumeRoleWithWebIdentity(
		ctx,
		AssumeRoleOptions{
			EndpointURL:      "https://storage.example.com",
			RoleARN:          "arn:aws:iam::123456789012:role/TestRole",
			WebIdentityToken: "test-token",
			RoleSessionName:  "test-session",
			SSLVerify:        true,
			SessionDuration:  time.Hour,
		},
	)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("AssumeRoleWithWebIdentity() error = %v, want context cancellation", err)
	}
}

func TestSTSRequestTimeout(t *testing.T) {
	if STSRequestTimeout <= 0 {
		t.Errorf("STSRequestTimeout should be positive, got %v", STSRequestTimeout)
	}
}
