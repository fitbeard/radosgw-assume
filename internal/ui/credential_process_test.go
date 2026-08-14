package ui

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/fitbeard/radosgw-assume/internal/config"
)

func TestFprintCredentialProcess(t *testing.T) {
	result := &config.AssumeRoleResult{
		AccessKeyID:     "access-key",
		SecretAccessKey: "secret-key",
		SessionToken:    "session-token",
		Expiration:      "2030-01-01T00:00:00Z",
		ProfileName:     "profile-must-not-be-emitted",
		EndpointURL:     "https://endpoint-must-not-be-emitted.example.com",
		AssumedRoleArn:  "arn:must-not-be-emitted",
	}
	var output bytes.Buffer
	if err := FprintCredentialProcess(&output, result); err != nil {
		t.Fatalf("FprintCredentialProcess() error = %v", err)
	}

	want := "{\"Version\":1,\"AccessKeyId\":\"access-key\",\"SecretAccessKey\":\"secret-key\",\"SessionToken\":\"session-token\",\"Expiration\":\"2030-01-01T00:00:00Z\"}\n"
	if output.String() != want {
		t.Errorf("FprintCredentialProcess() output = %q, want %q", output.String(), want)
	}
}

func TestFprintCredentialProcessWriteError(t *testing.T) {
	err := FprintCredentialProcess(credentialProcessErrorWriter{}, &config.AssumeRoleResult{})
	if err == nil || !strings.Contains(err.Error(), "write credential process output") {
		t.Errorf("FprintCredentialProcess() error = %v, want write error", err)
	}
}

type credentialProcessErrorWriter struct{}

func (credentialProcessErrorWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}
