package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/fitbeard/radosgw-assume/internal/sts"
	"github.com/fitbeard/radosgw-assume/pkg/duration"
)

type cliAction int

const (
	actionRun cliAction = iota
	actionHelp
	actionVersion
	actionExec
	actionShell
	actionCredentialProcess
	actionCacheStatus
	actionCacheClear
)

type cliOptions struct {
	action          cliAction
	profileName     string
	verbose         bool
	useEnv          bool
	showCredentials bool
	sessionDuration time.Duration
	sessionName     string
	noPrompt        bool
	noCache         bool
	command         []string
}

type positionalArgumentHandler func(*cliOptions, []string, int) (bool, error)

func parseCLIArguments(program string, args []string) (cliOptions, error) {
	if len(args) > 0 {
		switch args[0] {
		case "cache":
			return parseCacheArguments(program, args[1:])
		case "exec":
			return parseExecArguments(program, args[1:])
		case "shell":
			return parseShellArguments(program, args[1:])
		case "credential-process":
			return parseCredentialProcessArguments(program, args[1:])
		case "version":
			if len(args) == 1 {
				return newCLIOptions(actionVersion), nil
			}
		}
	}

	return parseRunArguments(program, args)
}

func parseRunArguments(program string, args []string) (cliOptions, error) {
	options, err := parseCommandOptions(program, args, actionRun, func(_ *cliOptions, args []string, index int) (bool, error) {
		argument := args[index]
		if argument == "--" {
			return false, fmt.Errorf("unexpected argument '--'\nUse -h or --help for usage information")
		}
		return false, fmt.Errorf("unexpected argument '%s': select a profile with -p or --profile\nUse -h or --help for usage information", argument)
	})
	if err != nil || options.action == actionHelp {
		return options, err
	}
	if err := validateCommandOptions(options); err != nil {
		return cliOptions{}, err
	}
	return options, nil
}

func parseExecArguments(program string, args []string) (cliOptions, error) {
	options, err := parseCommandOptions(program, args, actionExec, func(options *cliOptions, args []string, index int) (bool, error) {
		argument := args[index]
		if argument != "--" {
			return false, fmt.Errorf("unexpected exec argument '%s': command must follow '--'\nUsage: %s exec [OPTIONS] -- COMMAND [ARG...]", argument, program)
		}
		if index+1 >= len(args) {
			return false, execCommandRequiredError(program)
		}
		options.command = append([]string(nil), args[index+1:]...)
		return true, nil
	})
	if err != nil || options.action == actionHelp {
		return options, err
	}
	if len(options.command) == 0 {
		return cliOptions{}, execCommandRequiredError(program)
	}
	if err := validateCommandOptions(options); err != nil {
		return cliOptions{}, err
	}
	return options, nil
}

func parseShellArguments(program string, args []string) (cliOptions, error) {
	options, err := parseCommandOptions(program, args, actionShell, func(_ *cliOptions, args []string, index int) (bool, error) {
		argument := args[index]
		if argument == "--" {
			return false, fmt.Errorf("unexpected argument '--'\nUse -h or --help for usage information")
		}
		return false, fmt.Errorf("unexpected shell argument '%s'\nUsage: %s shell [OPTIONS]", argument, program)
	})
	if err != nil || options.action == actionHelp {
		return options, err
	}
	if err := validateCommandOptions(options); err != nil {
		return cliOptions{}, err
	}
	return options, nil
}

func parseCredentialProcessArguments(program string, args []string) (cliOptions, error) {
	options, err := parseCommandOptions(program, args, actionCredentialProcess, func(_ *cliOptions, args []string, index int) (bool, error) {
		argument := args[index]
		if argument == "--" {
			return false, fmt.Errorf("unexpected argument '--'\nUse -h or --help for usage information")
		}
		return false, fmt.Errorf("unexpected credential-process argument '%s'\nUsage: %s credential-process (-p PROFILE | --env)", argument, program)
	})
	if err != nil || options.action == actionHelp {
		return options, err
	}
	if err := validateConfigurationSource(options); err != nil {
		return cliOptions{}, err
	}
	if options.profileName == "" && !options.useEnv {
		return cliOptions{}, fmt.Errorf("credential-process requires -p/--profile or --env\nUsage: %s credential-process (-p PROFILE | --env)", program)
	}
	if err := validateScopedOptions(options); err != nil {
		return cliOptions{}, err
	}
	return options, nil
}

func parseCommandOptions(program string, args []string, action cliAction, handleArgument positionalArgumentHandler) (cliOptions, error) {
	options := newCLIOptions(action)
	for index := 0; index < len(args); index++ {
		done, handled, err := parseSharedOption(program, args, &index, &options)
		if err != nil {
			return cliOptions{}, err
		}
		if done {
			return options, nil
		}
		if handled {
			continue
		}

		argument := args[index]
		if strings.HasPrefix(argument, "-") && argument != "--" {
			return cliOptions{}, fmt.Errorf("unknown flag '%s'\nUse -h or --help for usage information", argument)
		}
		done, err = handleArgument(&options, args, index)
		if err != nil {
			return cliOptions{}, err
		}
		if done {
			return options, nil
		}
	}
	return options, nil
}

func parseSharedOption(program string, args []string, index *int, options *cliOptions) (done, handled bool, err error) {
	switch args[*index] {
	case "-h", "--help":
		options.action = actionHelp
		return true, true, nil
	case "-v", "--verbose":
		options.verbose = true
	case "--no-prompt":
		options.noPrompt = true
	case "--no-cache":
		options.noCache = true
	case "-e", "--env":
		options.useEnv = true
	case "--show-credentials":
		options.showCredentials = true
	case "-p", "--profile":
		if *index+1 >= len(args) || strings.HasPrefix(args[*index+1], "-") {
			return false, true, fmt.Errorf("profile flag requires a value\nUsage: %s -p PROFILE", program)
		}
		if options.profileName != "" {
			return false, true, fmt.Errorf("profile flag specified more than once\nUse -h or --help for usage information")
		}
		(*index)++
		options.profileName = args[*index]
		if options.profileName == "" {
			return false, true, fmt.Errorf("profile name cannot be empty")
		}
	case "-d", "--duration":
		if *index+1 >= len(args) {
			return false, true, fmt.Errorf("duration flag requires a value\nUsage: %s -d 1h [-p PROFILE]", program)
		}
		(*index)++
		durationValue := args[*index]
		sessionDuration, parseErr := duration.Parse(durationValue)
		if parseErr != nil {
			return false, true, fmt.Errorf("invalid duration '%s': %v\nValid formats: '3600' (seconds), '60m' (minutes), '1h' (hours)", durationValue, parseErr)
		}
		if validationErr := duration.Validate(sessionDuration); validationErr != nil {
			return false, true, validationErr
		}
		options.sessionDuration = sessionDuration
	case "-s", "--session":
		if *index+1 >= len(args) {
			return false, true, fmt.Errorf("session name flag requires a value\nUsage: %s -s my-session [-p PROFILE]", program)
		}
		(*index)++
		sessionName := args[*index]
		if validationErr := sts.ValidateSessionName(sessionName); validationErr != nil {
			return false, true, fmt.Errorf("invalid session name '%s': %v", sessionName, validationErr)
		}
		options.sessionName = sessionName
	default:
		return false, false, nil
	}
	return false, true, nil
}

func validateCommandOptions(options cliOptions) error {
	if err := validateConfigurationSource(options); err != nil {
		return err
	}
	return validateScopedOptions(options)
}

func validateConfigurationSource(options cliOptions) error {
	if options.useEnv && options.profileName != "" {
		return fmt.Errorf("--env and --profile cannot be used together")
	}
	return nil
}

func validateScopedOptions(options cliOptions) error {
	if options.showCredentials && options.action != actionRun {
		return fmt.Errorf("--show-credentials can only be used with the default export action")
	}
	if options.noPrompt && options.action != actionShell {
		return fmt.Errorf("--no-prompt can only be used with the shell command")
	}
	if options.noCache && options.action != actionCredentialProcess {
		return fmt.Errorf("--no-cache can only be used with the credential-process command")
	}
	return nil
}

func parseCacheArguments(program string, args []string) (cliOptions, error) {
	options := newCLIOptions(actionRun)
	if len(args) == 1 {
		switch args[0] {
		case "status":
			options.action = actionCacheStatus
			return options, nil
		case "clear":
			options.action = actionCacheClear
			return options, nil
		case "-h", "--help":
			options.action = actionHelp
			return options, nil
		}
	}
	if len(args) == 2 && (args[1] == "-h" || args[1] == "--help") {
		if args[0] == "status" || args[0] == "clear" {
			options.action = actionHelp
			return options, nil
		}
	}
	if len(args) == 0 {
		return cliOptions{}, fmt.Errorf("cache requires 'status' or 'clear'\nUsage: %s cache <status|clear>", program)
	}
	if args[0] != "status" && args[0] != "clear" {
		return cliOptions{}, fmt.Errorf("unknown cache command '%s'\nUsage: %s cache <status|clear>", args[0], program)
	}
	return cliOptions{}, fmt.Errorf("unexpected cache argument '%s'\nUsage: %s cache %s", args[1], program, args[0])
}

func newCLIOptions(action cliAction) cliOptions {
	return cliOptions{action: action, sessionDuration: time.Hour}
}

func execCommandRequiredError(program string) error {
	return fmt.Errorf("exec requires a command after '--'\nUsage: %s exec [OPTIONS] -- COMMAND [ARG...]", program)
}
