package main

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/fitbeard/radosgw-assume/internal/config"
	"github.com/fitbeard/radosgw-assume/internal/credentials"
	"github.com/fitbeard/radosgw-assume/internal/sts"
	"github.com/fitbeard/radosgw-assume/internal/ui"
	"github.com/fitbeard/radosgw-assume/internal/version"
	"github.com/fitbeard/radosgw-assume/pkg/duration"

	"gopkg.in/ini.v1"
)

type cliAction int

const (
	actionRun cliAction = iota
	actionHelp
	actionVersion
)

type cliOptions struct {
	action          cliAction
	profileName     string
	verbose         bool
	useEnv          bool
	sessionDuration time.Duration
	sessionName     string
}

type cliRunner struct {
	stdout io.Writer
	stderr io.Writer

	loadAWSConfig  func() (*ini.File, error)
	loadEnvConfig  func() (*config.ProfileConfig, error)
	getProfiles    func(*ini.File) []string
	getProfile     func(string, *ini.File) (*config.ProfileConfig, error)
	selectProfile  func([]string) (string, error)
	getCredentials func(string, *config.ProfileConfig, *ini.File, bool, time.Duration) (*config.AssumeRoleResult, error)
}

func newCLIRunner(stdout, stderr io.Writer) *cliRunner {
	return &cliRunner{
		stdout:         stdout,
		stderr:         stderr,
		loadAWSConfig:  config.LoadAWSConfig,
		loadEnvConfig:  config.GetProfileConfigFromEnv,
		getProfiles:    config.GetRadosGWProfiles,
		getProfile:     config.GetProfileConfig,
		selectProfile:  ui.SelectProfileInteractively,
		getCredentials: credentials.GetCredentials,
	}
}

func (r *cliRunner) run(program string, args []string) int {
	options, err := parseCLIArguments(program, args)
	if err != nil {
		_, _ = fmt.Fprintf(r.stderr, "Error: %v\n", err)
		return 1
	}

	switch options.action {
	case actionHelp:
		ui.FprintUsage(r.stdout)
		return 0
	case actionVersion:
		version.FprintVersion(r.stdout)
		return 0
	}

	profileName := options.profileName
	var profileConfig *config.ProfileConfig
	var awsConfig *ini.File

	if options.useEnv {
		profileConfig, err = r.loadEnvConfig()
		if err != nil {
			_, _ = fmt.Fprintf(r.stderr, "Error loading configuration from environment variables: %v\n", err)
			return 1
		}
		profileName = "env"
		if options.verbose {
			_, _ = fmt.Fprintln(r.stderr, "# Using configuration from environment variables")
		}
	} else {
		awsConfig, err = r.loadAWSConfig()
		if err != nil {
			_, _ = fmt.Fprintf(r.stderr, "Error loading AWS config: %v\n", err)
			return 1
		}

		if profileName == "" {
			profiles := r.getProfiles(awsConfig)
			if len(profiles) == 0 {
				_, _ = fmt.Fprintln(r.stderr, "No RadosGW profiles found in AWS config file")
				return 1
			}

			profileName, err = r.selectProfile(profiles)
			if err != nil {
				if errors.Is(err, ui.ErrSelectionCancelled) {
					return 0
				}
				_, _ = fmt.Fprintf(r.stderr, "Error: %v\n", err)
				return 1
			}
		}

		profileConfig, err = r.getProfile(profileName, awsConfig)
		if err != nil {
			_, _ = fmt.Fprintf(r.stderr, "Error: %v\n", err)
			return 1
		}
	}

	if options.sessionName != "" {
		profileConfig.RoleSessionName = options.sessionName
	}

	result, err := r.getCredentials(profileName, profileConfig, awsConfig, options.verbose, options.sessionDuration)
	if err != nil {
		_, _ = fmt.Fprintf(r.stderr, "Error: %v\n", err)
		return 1
	}

	if options.verbose {
		ui.FprintCredentials(r.stdout, r.stderr, result)
	} else {
		ui.FprintCredentialsOnly(r.stdout, result)
	}
	return 0
}

func parseCLIArguments(program string, args []string) (cliOptions, error) {
	options := cliOptions{sessionDuration: time.Hour}
	if len(args) == 1 && args[0] == "version" {
		options.action = actionVersion
		return options, nil
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]

		switch arg {
		case "-h", "--help":
			options.action = actionHelp
			return options, nil
		case "-v", "--verbose":
			options.verbose = true
		case "-e", "--env":
			options.useEnv = true
		case "-p", "--profile":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return cliOptions{}, fmt.Errorf("profile flag requires a value\nUsage: %s -p PROFILE", program)
			}
			if options.profileName != "" {
				return cliOptions{}, fmt.Errorf("profile flag specified more than once\nUse -h or --help for usage information")
			}
			i++
			options.profileName = args[i]
			if options.profileName == "" {
				return cliOptions{}, fmt.Errorf("profile name cannot be empty")
			}
		case "-d", "--duration":
			if i+1 >= len(args) {
				return cliOptions{}, fmt.Errorf("duration flag requires a value\nUsage: %s -d 1h [-p PROFILE]", program)
			}
			i++
			durationValue := args[i]
			sessionDuration, err := duration.Parse(durationValue)
			if err != nil {
				return cliOptions{}, fmt.Errorf("invalid duration '%s': %v\nValid formats: '3600' (seconds), '60m' (minutes), '1h' (hours)", durationValue, err)
			}
			if err := duration.Validate(sessionDuration); err != nil {
				return cliOptions{}, err
			}
			options.sessionDuration = sessionDuration
		case "-s", "--session":
			if i+1 >= len(args) {
				return cliOptions{}, fmt.Errorf("session name flag requires a value\nUsage: %s -s my-session [-p PROFILE]", program)
			}
			i++
			sessionName := args[i]
			if err := sts.ValidateSessionName(sessionName); err != nil {
				return cliOptions{}, fmt.Errorf("invalid session name '%s': %v", sessionName, err)
			}
			options.sessionName = sessionName
		default:
			if strings.HasPrefix(arg, "-") {
				return cliOptions{}, fmt.Errorf("unknown flag '%s'\nUse -h or --help for usage information", arg)
			}
			return cliOptions{}, fmt.Errorf("unexpected argument '%s': select a profile with -p or --profile\nUse -h or --help for usage information", arg)
		}
	}
	if options.useEnv && options.profileName != "" {
		return cliOptions{}, fmt.Errorf("--env and --profile cannot be used together")
	}

	return options, nil
}
