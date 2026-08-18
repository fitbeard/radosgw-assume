package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fitbeard/radosgw-assume/internal/config"
	"github.com/fitbeard/radosgw-assume/internal/credentialcache"
	"github.com/fitbeard/radosgw-assume/internal/credentials"
	"github.com/fitbeard/radosgw-assume/internal/ui"

	"gopkg.in/ini.v1"
)

const foregroundExportEnvironment = "RADOSGW_ASSUME_FOREGROUND_EXPORT"

type cliRunner struct {
	stdout io.Writer
	stderr io.Writer

	deferInteractiveExport bool

	loadAWSConfig         func() (*ini.File, error)
	loadEnvConfig         func() (*config.ProfileConfig, error)
	getProfiles           func(*ini.File) []string
	getProfile            func(string, *ini.File) (*config.ProfileConfig, error)
	selectProfile         func([]string) (string, error)
	getCredentials        func(context.Context, credentials.RequestOptions) (*config.AssumeRoleResult, error)
	getProcessCredentials func(context.Context, credentials.ProcessRequestOptions) (*config.AssumeRoleResult, error)
	inspectCache          func() (credentialcache.Summary, error)
	clearCache            func() (credentialcache.ClearResult, error)
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
		inspectCache:           credentialcache.Inspect,
		clearCache:             credentialcache.Clear,
		openTerminal:           openControllingTerminal,
		environ:                os.Environ,
		execCommand:            replaceProcess,
	}
}

func (r *cliRunner) run(program string, args []string) int {
	return r.runContext(context.Background(), program, args)
}

func (r *cliRunner) runContext(ctx context.Context, program string, args []string) int {
	options, err := parseCLIArguments(program, args)
	if err != nil {
		_, _ = fmt.Fprintf(r.stderr, "Error: %v\n", err)
		return 1
	}

	if exitCode, handled := r.runStandaloneAction(options); handled {
		return exitCode
	}
	if options.action == actionRun && options.profileName == "" && !options.useEnv && r.deferInteractiveExport {
		fprintForegroundExport(r.stdout, program, args)
		return 0
	}

	profile, exitCode := r.loadCLIProfile(options)
	if profile == nil {
		return exitCode
	}

	result, err := r.acquireCredentials(ctx, options, profile)
	if err != nil {
		return r.reportCredentialError(err)
	}
	return r.runCredentialAction(options, result)
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
