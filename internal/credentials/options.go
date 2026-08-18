package credentials

import (
	"io"
	"time"

	"github.com/fitbeard/radosgw-assume/internal/config"

	"gopkg.in/ini.v1"
)

// RequestOptions contains the inputs needed to obtain RadosGW credentials.
// Output receives authentication instructions and verbose diagnostics. When it
// is nil, GetCredentials writes them to standard error.
type RequestOptions struct {
	ProfileName     string
	ProfileConfig   *config.ProfileConfig
	AWSConfig       *ini.File
	Verbose         bool
	SessionDuration time.Duration
	Output          io.Writer
}

// ProcessRequestOptions contains credential-process-specific request options.
type ProcessRequestOptions struct {
	RequestOptions
	NoCache bool
}
