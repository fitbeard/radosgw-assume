package ui

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/fitbeard/radosgw-assume/internal/config"
)

type credentialProcessOutput struct {
	Version         int    `json:"Version"`
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken"`
	Expiration      string `json:"Expiration"`
}

// FprintCredentialProcess writes credentials using the AWS process credential
// provider JSON format.
func FprintCredentialProcess(w io.Writer, result *config.AssumeRoleResult) error {
	output := credentialProcessOutput{
		Version:         1,
		AccessKeyID:     result.AccessKeyID,
		SecretAccessKey: result.SecretAccessKey,
		SessionToken:    result.SessionToken,
		Expiration:      result.Expiration,
	}
	if err := json.NewEncoder(w).Encode(output); err != nil {
		return fmt.Errorf("write credential process output: %w", err)
	}
	return nil
}
