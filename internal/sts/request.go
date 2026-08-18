package sts

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/fitbeard/radosgw-assume/internal/config"
	"github.com/fitbeard/radosgw-assume/internal/httpclient"
)

// STSRequestTimeout bounds the complete role-assumption operation, including retries.
const STSRequestTimeout = 30 * time.Second

// AssumeRoleWithWebIdentity performs STS AssumeRoleWithWebIdentity operation
func AssumeRoleWithWebIdentity(ctx context.Context, endpointURL, roleArn, webIdentityToken, roleSessionName string, sslVerify bool, sessionDuration time.Duration) (*config.AssumeRoleResult, error) {
	return assumeRoleWithWebIdentity(ctx, endpointURL, roleArn, webIdentityToken, roleSessionName, sslVerify, sessionDuration, STSRequestTimeout)
}

func assumeRoleWithWebIdentity(ctx context.Context, endpointURL, roleArn, webIdentityToken, roleSessionName string, sslVerify bool, sessionDuration, requestTimeout time.Duration) (*config.AssumeRoleResult, error) {
	cfg := aws.Config{
		Credentials: aws.AnonymousCredentials{},
		HTTPClient:  httpclient.New(sslVerify, requestTimeout),
		Region:      "us-east-1",
	}

	stsClient := sts.NewFromConfig(cfg, func(o *sts.Options) {
		o.BaseEndpoint = aws.String(endpointURL)
	})

	input := &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          aws.String(roleArn),
		RoleSessionName:  aws.String(roleSessionName),
		DurationSeconds:  aws.Int32(int32(sessionDuration.Seconds())),
		WebIdentityToken: aws.String(webIdentityToken),
	}

	requestContext, cancelRequest := context.WithTimeout(ctx, requestTimeout)
	defer cancelRequest()

	result, err := stsClient.AssumeRoleWithWebIdentity(requestContext, input)
	if err != nil {
		return nil, formatSTSError(err, endpointURL, roleArn, sessionDuration)
	}

	return buildAssumeRoleResult(result, endpointURL)
}
