package credentials

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/fitbeard/radosgw-assume/internal/config"
	"github.com/fitbeard/radosgw-assume/internal/credentialcache"

	"gopkg.in/ini.v1"
)

type processCredentialCache interface {
	GetOrRetrieve(string, func() (*config.AssumeRoleResult, error)) (*config.AssumeRoleResult, bool, error)
}

type processCredentialDependencies struct {
	resolveSourceProfile func(*config.ProfileConfig, *ini.File, bool) (*config.ProfileConfig, error)
	getenv               func(string) string
	newCache             func(time.Duration) (processCredentialCache, error)
	getCredentials       func(context.Context, RequestOptions) (*config.AssumeRoleResult, error)
}

func newProcessCredentialDependencies() processCredentialDependencies {
	return processCredentialDependencies{
		resolveSourceProfile: config.ResolveSourceProfile,
		getenv:               os.Getenv,
		newCache: func(sessionDuration time.Duration) (processCredentialCache, error) {
			return credentialcache.New(sessionDuration)
		},
		getCredentials: GetCredentials,
	}
}

// GetProcessCredentials obtains credentials for the AWS process provider,
// reusing securely cached STS credentials unless caching is disabled.
func GetProcessCredentials(ctx context.Context, options ProcessRequestOptions) (*config.AssumeRoleResult, error) {
	return getProcessCredentials(ctx, options, newProcessCredentialDependencies())
}

func getProcessCredentials(ctx context.Context, options ProcessRequestOptions, dependencies processCredentialDependencies) (*config.AssumeRoleResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	output := options.Output
	if output == nil {
		output = os.Stderr
	}
	options.Output = output

	retrieve := func() (*config.AssumeRoleResult, error) {
		return dependencies.getCredentials(ctx, options.RequestOptions)
	}
	if options.NoCache {
		result, err := retrieve()
		if err != nil {
			return nil, err
		}
		reportProcessEndpoint(output, options.Verbose, result)
		return result, nil
	}

	effectiveConfig, err := dependencies.resolveSourceProfile(options.ProfileConfig, options.AWSConfig, false)
	if err != nil {
		return nil, err
	}
	cacheKey, err := credentialcache.Key(options.ProfileName, effectiveConfig, options.SessionDuration, dependencies.getenv("RADOSGW_OIDC_TOKEN"))
	if err != nil {
		return nil, err
	}
	cache, err := dependencies.newCache(options.SessionDuration)
	if err != nil {
		return nil, fmt.Errorf("initialize credential cache: %w", err)
	}

	result, cacheHit, err := cache.GetOrRetrieve(cacheKey, retrieve)
	if err != nil {
		return nil, err
	}
	if cacheHit {
		verbosef(output, options.Verbose, "# Using cached credentials for profile: %s\n", options.ProfileName)
	} else {
		reportProcessEndpoint(output, options.Verbose, result)
	}
	return result, nil
}

func reportProcessEndpoint(output io.Writer, verboseMode bool, result *config.AssumeRoleResult) {
	if result == nil || result.EndpointURL == "" {
		return
	}
	verbosef(output, verboseMode, "# Configure the AWS consumer endpoint separately: %s\n", result.EndpointURL)
}
