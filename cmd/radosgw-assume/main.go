package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fitbeard/radosgw-assume/internal/config"
	"github.com/fitbeard/radosgw-assume/internal/credentials"
	"github.com/fitbeard/radosgw-assume/internal/ui"
	"github.com/fitbeard/radosgw-assume/internal/version"
	"github.com/fitbeard/radosgw-assume/pkg/duration"

	"gopkg.in/ini.v1"
)

func main() {
	var profileName string
	var profileConfig *config.ProfileConfig
	var awsConfig *ini.File
	var err error
	var verboseMode = false
	var useEnv = false
	var sessionDuration = time.Hour // Default 1 hour

	// Parse command-line arguments
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		arg := args[i]

		switch arg {
		case "-h", "--help":
			ui.PrintUsage()
			os.Exit(0)
		case "version":
			version.PrintVersion()
			os.Exit(0)
		case "-v", "--verbose":
			verboseMode = true
		case "-e", "--env":
			useEnv = true
		case "-d", "--duration":
			if i+1 >= len(args) {
				fmt.Fprintf(os.Stderr, "Error: Duration flag requires a value\n")
				fmt.Fprintf(os.Stderr, "Usage: %s -d 1h [profile]\n", os.Args[0])
				os.Exit(1)
			}
			i++ // Move to the next argument (duration value)
			durationStr := args[i]
			sessionDuration, err = duration.Parse(durationStr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: Invalid duration '%s': %v\n", durationStr, err)
				fmt.Fprintf(os.Stderr, "Valid formats: '3600' (seconds), '60m' (minutes), '1h' (hours)\n")
				os.Exit(1)
			}
			if err := duration.Validate(sessionDuration); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		default:
			if strings.HasPrefix(arg, "-") {
				fmt.Fprintf(os.Stderr, "Error: Unknown flag '%s'\n", arg)
				fmt.Fprintf(os.Stderr, "Use -h or --help for usage information\n")
				os.Exit(1)
			}
			if profileName != "" {
				fmt.Fprintf(os.Stderr, "Error: Multiple profile names specified\n")
				fmt.Fprintf(os.Stderr, "Use -h or --help for usage information\n")
				os.Exit(1)
			}
			profileName = arg
		}
	}

	// Handle different configuration modes
	if useEnv {
		// Environment variable mode
		profileConfig, err = config.GetProfileConfigFromEnv()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading configuration from environment variables: %v\n", err)
			os.Exit(1)
		}
		profileName = "env"
		if verboseMode {
			fmt.Fprintf(os.Stderr, "# Using configuration from environment variables\n")
		}
	} else {
		// Load AWS config (used for both interactive and command-line modes)
		awsConfig = config.LoadAWSConfigOrEmpty(verboseMode)

		if profileName == "" {
			// Interactive mode - show profile selector
			profiles := config.GetRadosGWProfiles(awsConfig)
			if len(profiles) == 0 {
				fmt.Fprintf(os.Stderr, "No RadosGW profiles found in AWS config file\n")
				os.Exit(1)
			}

			selectedProfile, err := ui.SelectProfileInteractively(profiles)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			profileName = selectedProfile
		}
	}

	// Get profile config if not from environment
	if !useEnv {
		profileConfig, err = config.GetProfileConfig(profileName, awsConfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}

	// Get credentials
	result, err := credentials.GetCredentials(profileName, profileConfig, awsConfig, verboseMode, sessionDuration)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Output credentials
	if verboseMode {
		// Print with usage info when explicitly requested
		ui.PrintCredentials(result)
	} else {
		// Default: clean output without hints
		ui.PrintCredentialsOnly(result)
	}
}
