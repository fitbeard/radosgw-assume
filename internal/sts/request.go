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
func AssumeRoleWithWebIdentity(ctx context.Context, options AssumeRoleOptions) (*config.AssumeRoleResult, error) {
	return assumeRoleWithWebIdentity(ctx, options, STSRequestTimeout)
}

func assumeRoleWithWebIdentity(ctx context.Context, options AssumeRoleOptions, requestTimeout time.Duration) (*config.AssumeRoleResult, error) {
	cfg := aws.Config{
		Credentials: aws.AnonymousCredentials{},
		HTTPClient:  httpclient.New(options.SSLVerify, requestTimeout),
		Region:      "us-east-1",
	}

	stsClient := sts.NewFromConfig(cfg, func(o *sts.Options) {
		o.BaseEndpoint = aws.String(options.EndpointURL)
	})

	input := &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          aws.String(options.RoleARN),
		RoleSessionName:  aws.String(options.RoleSessionName),
		DurationSeconds:  aws.Int32(int32(options.SessionDuration.Seconds())),
		WebIdentityToken: aws.String(options.WebIdentityToken),
	}

	requestContext, cancelRequest := context.WithTimeout(ctx, requestTimeout)
	defer cancelRequest()

	result, err := stsClient.AssumeRoleWithWebIdentity(requestContext, input)
	if err != nil {
		return nil, formatSTSError(err, options.EndpointURL, options.RoleARN, options.SessionDuration)
	}

	return buildAssumeRoleResult(result, options.EndpointURL)
}
