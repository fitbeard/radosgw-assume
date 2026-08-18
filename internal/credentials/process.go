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
	getCredentials       func(context.Context, string, *config.ProfileConfig, *ini.File, bool, time.Duration, io.Writer) (*config.AssumeRoleResult, error)
}

func newProcessCredentialDependencies() processCredentialDependencies {
	return processCredentialDependencies{
		resolveSourceProfile: config.ResolveSourceProfile,
		getenv:               os.Getenv,
		newCache: func(sessionDuration time.Duration) (processCredentialCache, error) {
			return credentialcache.New(sessionDuration)
		},
		getCredentials: GetCredentialsWithOutput,
	}
}

// GetProcessCredentials obtains credentials for the AWS process provider,
// reusing securely cached STS credentials unless caching is disabled.
func GetProcessCredentials(ctx context.Context, profileName string, profileConfig *config.ProfileConfig, awsConfig *ini.File, verboseMode bool, sessionDuration time.Duration, output io.Writer, noCache bool) (*config.AssumeRoleResult, error) {
	return getProcessCredentials(
		ctx,
		profileName,
		profileConfig,
		awsConfig,
		verboseMode,
		sessionDuration,
		output,
		noCache,
		newProcessCredentialDependencies(),
	)
}

func getProcessCredentials(ctx context.Context, profileName string, profileConfig *config.ProfileConfig, awsConfig *ini.File, verboseMode bool, sessionDuration time.Duration, output io.Writer, noCache bool, dependencies processCredentialDependencies) (*config.AssumeRoleResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	retrieve := func() (*config.AssumeRoleResult, error) {
		return dependencies.getCredentials(ctx, profileName, profileConfig, awsConfig, verboseMode, sessionDuration, output)
	}
	if noCache {
		result, err := retrieve()
		if err != nil {
			return nil, err
		}
		reportProcessEndpoint(output, verboseMode, result)
		return result, nil
	}

	effectiveConfig, err := dependencies.resolveSourceProfile(profileConfig, awsConfig, false)
	if err != nil {
		return nil, err
	}
	cacheKey, err := credentialcache.Key(profileName, effectiveConfig, sessionDuration, dependencies.getenv("RADOSGW_OIDC_TOKEN"))
	if err != nil {
		return nil, err
	}
	cache, err := dependencies.newCache(sessionDuration)
	if err != nil {
		return nil, fmt.Errorf("initialize credential cache: %w", err)
	}

	result, cacheHit, err := cache.GetOrRetrieve(cacheKey, retrieve)
	if err != nil {
		return nil, err
	}
	if cacheHit {
		verbosef(output, verboseMode, "# Using cached credentials for profile: %s\n", profileName)
	} else {
		reportProcessEndpoint(output, verboseMode, result)
	}
	return result, nil
}

func reportProcessEndpoint(output io.Writer, verboseMode bool, result *config.AssumeRoleResult) {
	if result == nil || result.EndpointURL == "" {
		return
	}
	verbosef(output, verboseMode, "# Configure the AWS consumer endpoint separately: %s\n", result.EndpointURL)
}
