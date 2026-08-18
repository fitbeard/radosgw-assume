package auth

import (
	"context"
	"io"
	"net/http"
	"os"
	"time"
)

type deviceFlowProgress interface {
	Stop()
	StopQuiet()
}

type deviceFlowDependencies struct {
	stderr io.Writer

	generatePKCE      func(string) (string, string, string, error)
	newHTTPClient     func(bool) *http.Client
	discoverEndpoints func(context.Context, *http.Client, string) (oidcEndpoints, error)
	now               func() time.Time
	sleep             func(context.Context, time.Duration) error
	newProgress       func() deviceFlowProgress
}

func newDeviceFlowDependencies() deviceFlowDependencies {
	return deviceFlowDependencies{
		stderr:            os.Stderr,
		generatePKCE:      GeneratePKCE,
		newHTTPClient:     NewHTTPClient,
		discoverEndpoints: discoverOIDCEndpoints,
		now:               time.Now,
		sleep:             sleepWithContext,
		newProgress:       func() deviceFlowProgress { return NewProgressIndicator() },
	}
}
