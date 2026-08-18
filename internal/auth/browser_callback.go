package auth

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"strconv"
)

const callbackListenHost = "127.0.0.1"

type browserCallbackResult struct {
	code             string
	state            string
	errorCode        string
	errorDescription string
}

type browserCallbackServer struct {
	port     int
	errors   <-chan error
	shutdown func(context.Context) error
	close    func() error
}

func startBrowserCallbackServer(host string, ports []int, results chan<- browserCallbackResult) (*browserCallbackServer, error) {
	listener, port, err := listenOnCallbackPorts(host, ports...)
	if err != nil {
		return nil, err
	}

	server := &http.Server{
		Handler:           newBrowserCallbackHandler(results),
		ReadHeaderTimeout: CallbackReadHeaderTimeout,
	}
	serverErrors := make(chan error, 1)
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- err
		}
	}()

	return &browserCallbackServer{
		port:     port,
		errors:   serverErrors,
		shutdown: server.Shutdown,
		close:    server.Close,
	}, nil
}

func listenOnCallbackPorts(host string, ports ...int) (net.Listener, int, error) {
	if len(ports) == 0 {
		return nil, 0, fmt.Errorf("no callback ports configured")
	}

	var listenErrors []error
	for _, port := range ports {
		listener, err := net.Listen("tcp4", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			listenErrors = append(listenErrors, fmt.Errorf("port %d: %w", port, err))
			continue
		}

		boundPort := listener.Addr().(*net.TCPAddr).Port
		return listener, boundPort, nil
	}

	return nil, 0, errors.Join(listenErrors...)
}

func newBrowserCallbackHandler(results chan<- browserCallbackResult) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()

		if errorCode := query.Get("error"); errorCode != "" {
			errorDescription := query.Get("error_description")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintf(w, `
			<html lang="en">
			<head>
				<meta charset="UTF-8">
				<title>Authentication Failed</title>
				<style>
					body {
						background-color: #eee;
						margin: 0;
						padding: 0;
						font-family: sans-serif;
					}
					.placeholder {
						margin: 2em;
						padding: 2em;
						background-color: #fff;
						border-radius: 1em;
					}
				</style>
			</head>
			<body>
				<div class="placeholder">
					<h1>Authentication Failed</h1>
					<p>Error: %s</p>
					<p>Description: %s</p>
					<p>You can close this window and try again.</p>
				</div>
			</body>
			</html>
			`, html.EscapeString(errorCode), html.EscapeString(errorDescription))
			deliverBrowserCallbackResult(results, browserCallbackResult{
				errorCode:        errorCode,
				errorDescription: errorDescription,
			})
			return
		}

		code := query.Get("code")
		state := query.Get("state")
		if code == "" || state == "" {
			http.Error(w, "missing code or state", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, `
			<html lang="en">
			<head>
				<meta charset="UTF-8">
				<title>Authentication Successful</title>
				<script>setTimeout(function(){window.close()}, 3000);</script>
				<style>
					body {
						background-color: #eee;
						margin: 0;
						padding: 0;
						font-family: sans-serif;
					}
					.placeholder {
						margin: 2em;
						padding: 2em;
						background-color: #fff;
						border-radius: 1em;
					}
				</style>
			</head>
			<body>
				<div class="placeholder">
					<h1>Authentication Successful</h1>
					<p>You have successfully authenticated with RadosGW. You can now close this window and return to your terminal.</p>
				</div>
			</body>
			</html>
			`)
		deliverBrowserCallbackResult(results, browserCallbackResult{code: code, state: state})
	})

	return mux
}

func deliverBrowserCallbackResult(results chan<- browserCallbackResult, result browserCallbackResult) {
	select {
	case results <- result:
	default:
		// A callback has already completed the flow. Never block a duplicate or
		// late browser request while the server is shutting down.
	}
}
