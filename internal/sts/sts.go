package sts

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/fitbeard/radosgw-assume/internal/config"
)

// AssumeRoleWithWebIdentity performs STS AssumeRoleWithWebIdentity operation
func AssumeRoleWithWebIdentity(endpointURL, roleArn, webIdentityToken, sessionName string, sslVerify bool, sessionDuration time.Duration) (*config.AssumeRoleResult, error) {
	// Create STS client with anonymous credentials
	cfg := aws.Config{
		Credentials: aws.AnonymousCredentials{},
		Region: "us-east-1", // Required by AWS SDK, but not used by RadosGW
	}

	// Configure HTTP client for SSL verification
	if !sslVerify {
		cfg.HTTPClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
	}

	stsClient := sts.NewFromConfig(cfg, func(o *sts.Options) {
		o.BaseEndpoint = aws.String(endpointURL)
	})

	// Assume role with web identity
	input := &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          aws.String(roleArn),
		RoleSessionName:  aws.String(fmt.Sprintf("radosgw-assume-%s", sessionName)),
		DurationSeconds:  aws.Int32(int32(sessionDuration.Seconds())),
		WebIdentityToken: aws.String(webIdentityToken),
	}

	result, err := stsClient.AssumeRoleWithWebIdentity(context.TODO(), input)
	if err != nil {
		return nil, err
	}

	// Format expiration time
	expiration := result.Credentials.Expiration.Format(time.RFC3339)

	return &config.AssumeRoleResult{
		AccessKeyID:     *result.Credentials.AccessKeyId,
		SecretAccessKey: *result.Credentials.SecretAccessKey,
		SessionToken:    *result.Credentials.SessionToken,
		Expiration:      expiration,
		ProfileName:     sessionName,
		EndpointURL:     endpointURL,
	}, nil
}
