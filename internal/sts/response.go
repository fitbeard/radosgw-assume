package sts

import (
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/fitbeard/radosgw-assume/internal/config"
)

func buildAssumeRoleResult(result *sts.AssumeRoleWithWebIdentityOutput, endpointURL string) (*config.AssumeRoleResult, error) {
	if result == nil {
		return nil, fmt.Errorf("STS endpoint '%s' returned an invalid response: response is missing", endpointURL)
	}
	if result.Credentials == nil {
		return nil, fmt.Errorf("STS endpoint '%s' returned an invalid response: credentials are missing", endpointURL)
	}

	credentials := result.Credentials
	var missingFields []string
	if aws.ToString(credentials.AccessKeyId) == "" {
		missingFields = append(missingFields, "AccessKeyId")
	}
	if aws.ToString(credentials.SecretAccessKey) == "" {
		missingFields = append(missingFields, "SecretAccessKey")
	}
	if aws.ToString(credentials.SessionToken) == "" {
		missingFields = append(missingFields, "SessionToken")
	}
	if credentials.Expiration == nil || credentials.Expiration.IsZero() {
		missingFields = append(missingFields, "Expiration")
	}
	if len(missingFields) > 0 {
		return nil, fmt.Errorf(
			"STS endpoint '%s' returned an invalid response: missing required credential fields: %s",
			endpointURL,
			strings.Join(missingFields, ", "),
		)
	}

	var assumedRoleArn string
	if result.AssumedRoleUser != nil && result.AssumedRoleUser.Arn != nil {
		assumedRoleArn = *result.AssumedRoleUser.Arn
	}

	return &config.AssumeRoleResult{
		AssumedRoleArn:  assumedRoleArn,
		AccessKeyID:     aws.ToString(credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(credentials.SecretAccessKey),
		SessionToken:    aws.ToString(credentials.SessionToken),
		Expiration:      credentials.Expiration.Format(time.RFC3339),
		EndpointURL:     endpointURL,
	}, nil
}
