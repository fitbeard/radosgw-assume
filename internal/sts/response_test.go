package sts

import (
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awssts "github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
)

func TestBuildAssumeRoleResultRejectsIncompleteCredentials(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(*awssts.AssumeRoleWithWebIdentityOutput) *awssts.AssumeRoleWithWebIdentityOutput
		wantContain string
	}{
		{
			name:        "missing response",
			mutate:      func(*awssts.AssumeRoleWithWebIdentityOutput) *awssts.AssumeRoleWithWebIdentityOutput { return nil },
			wantContain: "response is missing",
		},
		{
			name: "missing credentials",
			mutate: func(output *awssts.AssumeRoleWithWebIdentityOutput) *awssts.AssumeRoleWithWebIdentityOutput {
				output.Credentials = nil
				return output
			},
			wantContain: "credentials are missing",
		},
		{
			name: "missing access key ID",
			mutate: func(output *awssts.AssumeRoleWithWebIdentityOutput) *awssts.AssumeRoleWithWebIdentityOutput {
				output.Credentials.AccessKeyId = nil
				return output
			},
			wantContain: "AccessKeyId",
		},
		{
			name: "empty access key ID",
			mutate: func(output *awssts.AssumeRoleWithWebIdentityOutput) *awssts.AssumeRoleWithWebIdentityOutput {
				output.Credentials.AccessKeyId = aws.String("")
				return output
			},
			wantContain: "AccessKeyId",
		},
		{
			name: "missing secret access key",
			mutate: func(output *awssts.AssumeRoleWithWebIdentityOutput) *awssts.AssumeRoleWithWebIdentityOutput {
				output.Credentials.SecretAccessKey = nil
				return output
			},
			wantContain: "SecretAccessKey",
		},
		{
			name: "missing session token",
			mutate: func(output *awssts.AssumeRoleWithWebIdentityOutput) *awssts.AssumeRoleWithWebIdentityOutput {
				output.Credentials.SessionToken = nil
				return output
			},
			wantContain: "SessionToken",
		},
		{
			name: "missing expiration",
			mutate: func(output *awssts.AssumeRoleWithWebIdentityOutput) *awssts.AssumeRoleWithWebIdentityOutput {
				output.Credentials.Expiration = nil
				return output
			},
			wantContain: "Expiration",
		},
		{
			name: "zero expiration",
			mutate: func(output *awssts.AssumeRoleWithWebIdentityOutput) *awssts.AssumeRoleWithWebIdentityOutput {
				output.Credentials.Expiration = aws.Time(time.Time{})
				return output
			},
			wantContain: "Expiration",
		},
		{
			name: "multiple missing fields",
			mutate: func(output *awssts.AssumeRoleWithWebIdentityOutput) *awssts.AssumeRoleWithWebIdentityOutput {
				output.Credentials.AccessKeyId = nil
				output.Credentials.SessionToken = nil
				return output
			},
			wantContain: "AccessKeyId, SessionToken",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := buildAssumeRoleResult(test.mutate(completeAssumeRoleOutput()), "https://s3.example.com")
			if err == nil {
				t.Fatal("buildAssumeRoleResult() expected an error")
			}
			if result != nil {
				t.Errorf("buildAssumeRoleResult() result = %#v, want nil", result)
			}
			if !strings.Contains(err.Error(), test.wantContain) {
				t.Errorf("buildAssumeRoleResult() error = %v, want to contain %q", err, test.wantContain)
			}
			if !strings.Contains(err.Error(), "https://s3.example.com") {
				t.Errorf("buildAssumeRoleResult() error = %v, want endpoint context", err)
			}
		})
	}
}

func TestBuildAssumeRoleResultAllowsMissingAssumedRoleUser(t *testing.T) {
	output := completeAssumeRoleOutput()
	output.AssumedRoleUser = nil

	result, err := buildAssumeRoleResult(output, "https://s3.example.com")
	if err != nil {
		t.Fatalf("buildAssumeRoleResult() error = %v", err)
	}
	if result.AssumedRoleArn != "" {
		t.Errorf("AssumedRoleArn = %q, want empty", result.AssumedRoleArn)
	}
	if result.Expiration != "2030-01-01T00:00:00Z" {
		t.Errorf("Expiration = %q, want RFC3339 timestamp", result.Expiration)
	}
}

func completeAssumeRoleOutput() *awssts.AssumeRoleWithWebIdentityOutput {
	expiration := time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)
	return &awssts.AssumeRoleWithWebIdentityOutput{
		AssumedRoleUser: &types.AssumedRoleUser{
			Arn: aws.String("arn:aws:sts::123456789012:assumed-role/TestRole/test-session"),
		},
		Credentials: &types.Credentials{
			AccessKeyId:     aws.String("test-access-key"),
			SecretAccessKey: aws.String("test-secret-key"),
			SessionToken:    aws.String("test-session-token"),
			Expiration:      aws.Time(expiration),
		},
	}
}
