package main

import (
	"errors"
	"fmt"
	"io"
	"os"
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
	actionExec
	actionShell
	actionCredentialProcess
)

const foregroundExportEnvironment = "RADOSGW_ASSUME_FOREGROUND_EXPORT"

type cliOptions struct {
	action          cliAction
	profileName     string
	verbose         bool
	useEnv          bool
	sessionDuration time.Duration
	sessionName     string
	noPrompt        bool
	noCache         bool
	command         []string
}

type cliRunner struct {
	stdout io.Writer
	stderr io.Writer

	deferInteractiveExport bool

	loadAWSConfig         func() (*ini.File, error)
	loadEnvConfig         func() (*config.ProfileConfig, error)
	getProfiles           func(*ini.File) []string
	getProfile            func(string, *ini.File) (*config.ProfileConfig, error)
	selectProfile         func([]string) (string, error)
	getCredentials        func(string, *config.ProfileConfig, *ini.File, bool, time.Duration) (*config.AssumeRoleResult, error)
	getProcessCredentials func(string, *config.ProfileConfig, *ini.File, bool, time.Duration, io.Writer, bool) (*config.AssumeRoleResult, error)
	openTerminal          func() (io.WriteCloser, error)
	environ               func() []string
	execCommand           func([]string, []string) error
}

func newCLIRunner(stdout, stderr io.Writer) *cliRunner {
	return &cliRunner{
		stdout:                 stdout,
		stderr:                 stderr,
		deferInteractiveExport: shouldDeferInteractiveExport(stdout, processIsForeground()),
		loadAWSConfig:          config.LoadAWSConfig,
		loadEnvConfig:          config.GetProfileConfigFromEnv,
		getProfiles:            config.GetRadosGWProfiles,
		getProfile:             config.GetProfileConfig,
		selectProfile:          ui.SelectProfileInteractively,
		getCredentials:         credentials.GetCredentials,
		getProcessCredentials:  credentials.GetProcessCredentials,
		openTerminal:           openControllingTerminal,
		environ:                os.Environ,
		execCommand:            replaceProcess,
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
	if options.action == actionRun && options.profileName == "" && !options.useEnv && r.deferInteractiveExport {
		fprintForegroundExport(r.stdout, program, args)
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

	var result *config.AssumeRoleResult
	if options.action == actionCredentialProcess {
		authenticationOutput := r.stderr
		terminal, terminalErr := r.openTerminal()
		if terminalErr == nil && terminal != nil {
			defer func() { _ = terminal.Close() }()
			authenticationOutput = terminal
		}
		result, err = r.getProcessCredentials(profileName, profileConfig, awsConfig, options.verbose, options.sessionDuration, authenticationOutput, options.noCache)
	} else {
		result, err = r.getCredentials(profileName, profileConfig, awsConfig, options.verbose, options.sessionDuration)
	}
	if err != nil {
		_, _ = fmt.Fprintf(r.stderr, "Error: %v\n", err)
		return 1
	}
	if options.action == actionExec {
		if err := r.execCommand(options.command, credentialEnvironment(r.environ(), result)); err != nil {
			_, _ = fmt.Fprintf(r.stderr, "Error: %v\n", err)
			return 1
		}
		return 0
	}
	if options.action == actionShell {
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
	if options.action == actionCredentialProcess {
		if err := ui.FprintCredentialProcess(r.stdout, result); err != nil {
			_, _ = fmt.Fprintf(r.stderr, "Error: %v\n", err)
			return 1
		}
		return 0
	}

	if options.verbose {
		ui.FprintCredentials(r.stdout, r.stderr, result)
	} else {
		ui.FprintCredentialsOnly(r.stdout, result)
	}
	return 0
}

func openControllingTerminal() (io.WriteCloser, error) {
	return os.OpenFile("/dev/tty", os.O_WRONLY, 0)
}

func shouldDeferInteractiveExport(output io.Writer, processForeground bool) bool {
	if os.Getenv(foregroundExportEnvironment) != "" {
		return false
	}
	file, ok := output.(*os.File)
	if !ok {
		return false
	}
	fileInfo, err := file.Stat()
	return err == nil && fileInfo.Mode()&os.ModeNamedPipe != 0 && !processForeground
}

func fprintForegroundExport(w io.Writer, program string, args []string) {
	command := make([]string, 0, len(args)+1)
	command = append(command, ui.ShellQuote(program))
	for _, arg := range args {
		command = append(command, ui.ShellQuote(arg))
	}
	_, _ = fmt.Fprintf(w, "eval \"$(%s=1 %s)\"\n", foregroundExportEnvironment, strings.Join(command, " "))
}

func parseCLIArguments(program string, args []string) (cliOptions, error) {
	options := cliOptions{sessionDuration: time.Hour}
	if len(args) == 1 && args[0] == "version" {
		options.action = actionVersion
		return options, nil
	}
	startIndex := 0
	if len(args) > 0 {
		switch args[0] {
		case "exec":
			options.action = actionExec
			startIndex = 1
		case "shell":
			options.action = actionShell
			startIndex = 1
		case "credential-process":
			options.action = actionCredentialProcess
			startIndex = 1
		}
	}

	for i := startIndex; i < len(args); i++ {
		arg := args[i]

		switch arg {
		case "--":
			if options.action != actionExec {
				return cliOptions{}, fmt.Errorf("unexpected argument '--'\nUse -h or --help for usage information")
			}
			if i+1 >= len(args) {
				return cliOptions{}, fmt.Errorf("exec requires a command after '--'\nUsage: %s exec [OPTIONS] -- COMMAND [ARG...]", program)
			}
			options.command = append([]string(nil), args[i+1:]...)
			i = len(args)
		case "-h", "--help":
			options.action = actionHelp
			return options, nil
		case "-v", "--verbose":
			options.verbose = true
		case "--no-prompt":
			options.noPrompt = true
		case "--no-cache":
			options.noCache = true
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
			if options.action == actionExec {
				return cliOptions{}, fmt.Errorf("unexpected exec argument '%s': command must follow '--'\nUsage: %s exec [OPTIONS] -- COMMAND [ARG...]", arg, program)
			}
			if options.action == actionShell {
				return cliOptions{}, fmt.Errorf("unexpected shell argument '%s'\nUsage: %s shell [OPTIONS]", arg, program)
			}
			if options.action == actionCredentialProcess {
				return cliOptions{}, fmt.Errorf("unexpected credential-process argument '%s'\nUsage: %s credential-process (-p PROFILE | --env)", arg, program)
			}
			return cliOptions{}, fmt.Errorf("unexpected argument '%s': select a profile with -p or --profile\nUse -h or --help for usage information", arg)
		}
	}
	if options.action == actionExec && len(options.command) == 0 {
		return cliOptions{}, fmt.Errorf("exec requires a command after '--'\nUsage: %s exec [OPTIONS] -- COMMAND [ARG...]", program)
	}
	if options.useEnv && options.profileName != "" {
		return cliOptions{}, fmt.Errorf("--env and --profile cannot be used together")
	}
	if options.action == actionCredentialProcess && options.profileName == "" && !options.useEnv {
		return cliOptions{}, fmt.Errorf("credential-process requires -p/--profile or --env\nUsage: %s credential-process (-p PROFILE | --env)", program)
	}
	if options.noPrompt && options.action != actionShell {
		return cliOptions{}, fmt.Errorf("--no-prompt can only be used with the shell command")
	}
	if options.noCache && options.action != actionCredentialProcess {
		return cliOptions{}, fmt.Errorf("--no-cache can only be used with the credential-process command")
	}

	return options, nil
}

func credentialEnvironment(environment []string, result *config.AssumeRoleResult) []string {
	overrides := []string{
		"AWS_ACCESS_KEY_ID=" + result.AccessKeyID,
		"AWS_SECRET_ACCESS_KEY=" + result.SecretAccessKey,
		"AWS_SESSION_TOKEN=" + result.SessionToken,
		"AWS_ENDPOINT_URL=" + result.EndpointURL,
		"AWS_CREDENTIAL_EXPIRATION=" + result.Expiration,
		"AWS_SESSION_EXPIRATION=" + result.Expiration,
	}
	if result.ProfileName != "env" {
		overrides = append(overrides, "AWS_PROFILE="+result.ProfileName)
	}

	// The OIDC token is only needed to obtain temporary credentials and must not
	// be exposed to the executed command.
	return environmentWithOverrides(environment, overrides, "RADOSGW_OIDC_TOKEN")
}

func shellEnvironment(environment []string, result *config.AssumeRoleResult) []string {
	return environmentWithOverrides(credentialEnvironment(environment, result), []string{
		"RADOSGW_ASSUME_SHELL=1",
		"RADOSGW_ASSUME_PROFILE=" + result.ProfileName,
		"RADOSGW_ASSUME_PROMPT_LABEL=" + promptLabel(result.ProfileName),
	})
}

func environmentWithOverrides(environment, overrides []string, removedNames ...string) []string {
	overriddenNames := make(map[string]struct{}, len(overrides)+len(removedNames))
	for _, variable := range overrides {
		name, _, _ := strings.Cut(variable, "=")
		overriddenNames[name] = struct{}{}
	}
	for _, name := range removedNames {
		overriddenNames[name] = struct{}{}
	}

	childEnvironment := make([]string, 0, len(environment)+len(overrides))
	for _, variable := range environment {
		name, _, _ := strings.Cut(variable, "=")
		if _, overridden := overriddenNames[name]; !overridden {
			childEnvironment = append(childEnvironment, variable)
		}
	}

	return append(childEnvironment, overrides...)
}
