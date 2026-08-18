package main

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/fitbeard/radosgw-assume/internal/config"
	"github.com/fitbeard/radosgw-assume/internal/credentialcache"
	"github.com/fitbeard/radosgw-assume/internal/ui"
	"github.com/fitbeard/radosgw-assume/internal/version"

	"gopkg.in/ini.v1"
)

type cliProfile struct {
	name          string
	profileConfig *config.ProfileConfig
	awsConfig     *ini.File
}

func (r *cliRunner) runStandaloneAction(options cliOptions) (int, bool) {
	switch options.action {
	case actionHelp:
		ui.FprintUsage(r.stdout)
		return 0, true
	case actionVersion:
		version.FprintVersion(r.stdout)
		return 0, true
	case actionCacheStatus:
		summary, err := r.inspectCache()
		if err != nil {
			_, _ = fmt.Fprintf(r.stderr, "Error inspecting credential cache: %v\n", err)
			return 1, true
		}
		fprintCacheStatus(r.stdout, summary)
		return 0, true
	case actionCacheClear:
		result, err := r.clearCache()
		if err != nil {
			_, _ = fmt.Fprintf(r.stderr, "Error clearing credential cache: %v\n", err)
			return 1, true
		}
		_, _ = fmt.Fprintf(r.stdout, "Cleared %d credential cache entries from %s\n", result.Removed, result.Directory)
		return 0, true
	default:
		return 0, false
	}
}

func (r *cliRunner) loadCLIProfile(options cliOptions) (*cliProfile, int) {
	profileName := options.profileName
	var profileConfig *config.ProfileConfig
	var awsConfig *ini.File
	var err error

	if options.useEnv {
		profileConfig, err = r.loadEnvConfig()
		if err != nil {
			_, _ = fmt.Fprintf(r.stderr, "Error loading configuration from environment variables: %v\n", err)
			return nil, 1
		}
		profileName = "env"
		if options.verbose {
			_, _ = fmt.Fprintln(r.stderr, "# Using configuration from environment variables")
		}
	} else {
		awsConfig, err = r.loadAWSConfig()
		if err != nil {
			_, _ = fmt.Fprintf(r.stderr, "Error loading AWS config: %v\n", err)
			return nil, 1
		}

		if profileName == "" {
			profiles := r.getProfiles(awsConfig)
			if len(profiles) == 0 {
				_, _ = fmt.Fprintln(r.stderr, "No RadosGW profiles found in AWS config file")
				return nil, 1
			}

			profileName, err = r.selectProfile(profiles)
			if err != nil {
				if errors.Is(err, ui.ErrSelectionCancelled) {
					return nil, 0
				}
				_, _ = fmt.Fprintf(r.stderr, "Error: %v\n", err)
				return nil, 1
			}
		}

		profileConfig, err = r.getProfile(profileName, awsConfig)
		if err != nil {
			_, _ = fmt.Fprintf(r.stderr, "Error: %v\n", err)
			return nil, 1
		}
	}

	if options.sessionName != "" {
		profileConfig.RoleSessionName = options.sessionName
	}

	return &cliProfile{name: profileName, profileConfig: profileConfig, awsConfig: awsConfig}, 0
}

func (r *cliRunner) acquireCredentials(ctx context.Context, options cliOptions, profile *cliProfile) (*config.AssumeRoleResult, error) {
	if options.action == actionCredentialProcess {
		authenticationOutput := r.stderr
		terminal, terminalErr := r.openTerminal()
		if terminalErr == nil && terminal != nil {
			defer func() { _ = terminal.Close() }()
			authenticationOutput = terminal
		}
		return r.getProcessCredentials(
			ctx,
			profile.name,
			profile.profileConfig,
			profile.awsConfig,
			options.verbose,
			options.sessionDuration,
			authenticationOutput,
			options.noCache,
		)
	}
	return r.getCredentials(
		ctx,
		profile.name,
		profile.profileConfig,
		profile.awsConfig,
		options.verbose,
		options.sessionDuration,
	)
}

func (r *cliRunner) reportCredentialError(err error) int {
	if errors.Is(err, context.Canceled) {
		return 130
	}
	_, _ = fmt.Fprintf(r.stderr, "Error: %v\n", err)
	return 1
}

func (r *cliRunner) runCredentialAction(options cliOptions, result *config.AssumeRoleResult) int {
	switch options.action {
	case actionExec:
		return r.runExecAction(options.command, result)
	case actionShell:
		return r.runShellAction(options, result)
	case actionCredentialProcess:
		if err := ui.FprintCredentialProcess(r.stdout, result); err != nil {
			_, _ = fmt.Fprintf(r.stderr, "Error: %v\n", err)
			return 1
		}
		return 0
	default:
		if options.verbose {
			ui.FprintCredentials(r.stdout, r.stderr, result)
		} else {
			ui.FprintCredentialsOnly(r.stdout, result)
		}
		return 0
	}
}

func (r *cliRunner) runExecAction(command []string, result *config.AssumeRoleResult) int {
	if err := r.execCommand(command, credentialEnvironment(r.environ(), result)); err != nil {
		_, _ = fmt.Fprintf(r.stderr, "Error: %v\n", err)
		return 1
	}
	return 0
}

func (r *cliRunner) runShellAction(options cliOptions, result *config.AssumeRoleResult) int {
	environment := shellEnvironment(r.environ(), result)
	launch, err := prepareInteractiveShell(environment, !options.noPrompt)
	if err != nil {
		_, _ = fmt.Fprintf(r.stderr, "Error preparing interactive shell: %v\n", err)
		return 1
	}
	defer launch.cleanup()

	_, _ = fmt.Fprintf(r.stderr, "# Entering RadosGW shell for profile: %s\n", result.ProfileName)
	_, _ = fmt.Fprintf(r.stderr, "# Credentials valid until: %s\n", result.Expiration)
	if launch.promptModified {
		_, _ = fmt.Fprintf(r.stderr, "# Prompt marker: [%s]\n", promptLabel(result.ProfileName))
	}
	_, _ = fmt.Fprintln(r.stderr, "# Type 'exit' or press Ctrl+D to return.")
	if err := r.execCommand(launch.command, launch.environment); err != nil {
		_, _ = fmt.Fprintf(r.stderr, "Error: %v\n", err)
		return 1
	}
	return 0
}

func fprintCacheStatus(w io.Writer, summary credentialcache.Summary) {
	_, _ = fmt.Fprintf(w, "Credential cache: %s\n", summary.Directory)
	_, _ = fmt.Fprintf(w, "Entries: %d\n", summary.Total())
	if summary.Total() > 0 {
		_, _ = fmt.Fprintf(w, "  Valid: %d\n", summary.Valid)
		_, _ = fmt.Fprintf(w, "  Expired: %d\n", summary.Expired)
		_, _ = fmt.Fprintf(w, "  Invalid: %d\n", summary.Invalid)
	}
}
