// Package httpclient provides HTTP clients with the shared transport behavior
// required by RadosGW and OIDC endpoints.
package httpclient

import (
	"crypto/tls"
	"net/http"
	"time"
)

// New returns an HTTP client with the supplied timeout. When TLS verification
// is disabled, the default transport is cloned so its proxy, connection pool,
// and HTTP/2 settings are preserved without mutating global state.
func New(verifyTLS bool, requestTimeout time.Duration) *http.Client {
	client := &http.Client{Timeout: requestTimeout}
	if !verifyTLS {
		client.Transport = insecureDefaultTransport()
	}
	return client
}

func insecureDefaultTransport() *http.Transport {
	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		defaultTransport = &http.Transport{Proxy: http.ProxyFromEnvironment}
	}

	transport := defaultTransport.Clone()
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	}
	transport.TLSClientConfig.InsecureSkipVerify = true

	return transport
}
