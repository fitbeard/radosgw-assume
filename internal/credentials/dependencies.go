package credentials

import (
	"context"
	"io"
	"os"
	"time"

	"github.com/fitbeard/radosgw-assume/internal/auth"
	"github.com/fitbeard/radosgw-assume/internal/config"
	"github.com/fitbeard/radosgw-assume/internal/sts"

	"gopkg.in/ini.v1"
)

type credentialDependencies struct {
	stderr io.Writer
	getenv func(string) string
	now    func() time.Time

	resolveSourceProfile func(*config.ProfileConfig, *ini.File, bool) (*config.ProfileConfig, error)
	authenticateDevice   func(context.Context, auth.OIDCOptions) (string, error)
	authenticateBrowser  func(context.Context, auth.OIDCOptions) (string, error)
	assumeRole           func(context.Context, sts.AssumeRoleOptions) (*config.AssumeRoleResult, error)
}

func newCredentialDependencies() credentialDependencies {
	return credentialDependencies{
		stderr:               os.Stderr,
		getenv:               os.Getenv,
		now:                  time.Now,
		resolveSourceProfile: config.ResolveSourceProfile,
		authenticateDevice:   auth.AuthenticateDeviceFlow,
		authenticateBrowser:  auth.AuthenticateBrowserFlow,
		assumeRole:           sts.AssumeRoleWithWebIdentity,
	}
}
