package auth

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestListenOnCallbackPorts(t *testing.T) {
	t.Run("keeps selected port reserved", func(t *testing.T) {
		listener, port, err := listenOnCallbackPorts("127.0.0.1", 0)
		if err != nil {
			t.Fatalf("listenOnCallbackPorts() error = %v", err)
		}
		t.Cleanup(func() { _ = listener.Close() })

		duplicate, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			_ = duplicate.Close()
			t.Fatal("selected callback port was not kept reserved")
		}
	})

	t.Run("falls back when first port is busy", func(t *testing.T) {
		occupied, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to occupy first port: %v", err)
		}
		t.Cleanup(func() { _ = occupied.Close() })
		occupiedPort := occupied.Addr().(*net.TCPAddr).Port

		listener, port, err := listenOnCallbackPorts("127.0.0.1", occupiedPort, 0)
		if err != nil {
			t.Fatalf("listenOnCallbackPorts() error = %v", err)
		}
		t.Cleanup(func() { _ = listener.Close() })

		if port == occupiedPort {
			t.Errorf("selected port = %d, want a fallback port", port)
		}
	})

	t.Run("reports when all ports are busy", func(t *testing.T) {
		first, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to occupy first port: %v", err)
		}
		t.Cleanup(func() { _ = first.Close() })

		second, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to occupy second port: %v", err)
		}
		t.Cleanup(func() { _ = second.Close() })

		_, _, err = listenOnCallbackPorts(
			"127.0.0.1",
			first.Addr().(*net.TCPAddr).Port,
			second.Addr().(*net.TCPAddr).Port,
		)
		if err == nil {
			t.Fatal("listenOnCallbackPorts() expected an error")
		}
	})

	t.Run("rejects an empty port list", func(t *testing.T) {
		_, _, err := listenOnCallbackPorts("127.0.0.1")
		if err == nil {
			t.Fatal("listenOnCallbackPorts() expected an error")
		}
	})
}

func TestBrowserCallbackHandler(t *testing.T) {
	t.Run("delivers authorization code", func(t *testing.T) {
		results := make(chan browserCallbackResult, 1)
		handler := newBrowserCallbackHandler(results)
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/callback?code=test-code&state=test-state", nil)

		handler.ServeHTTP(response, request)

		if response.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", response.Code, http.StatusOK)
		}
		result := <-results
		if result.code != "test-code" || result.state != "test-state" {
			t.Errorf("result = %+v, want code and state", result)
		}
	})

	t.Run("delivers provider error and escapes response", func(t *testing.T) {
		results := make(chan browserCallbackResult, 1)
		handler := newBrowserCallbackHandler(results)
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/callback?error=access_denied&error_description=%3Cscript%3Ealert(1)%3C/script%3E", nil)

		handler.ServeHTTP(response, request)

		if response.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", response.Code, http.StatusBadRequest)
		}
		if strings.Contains(response.Body.String(), "<script>alert(1)</script>") {
			t.Error("error description was not HTML-escaped")
		}
		result := <-results
		if result.errorCode != "access_denied" || result.errorDescription != "<script>alert(1)</script>" {
			t.Errorf("result = %+v, want provider error", result)
		}
	})

	t.Run("rejects incomplete callback without completing flow", func(t *testing.T) {
		results := make(chan browserCallbackResult, 1)
		handler := newBrowserCallbackHandler(results)
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/callback?code=test-code", nil)

		handler.ServeHTTP(response, request)

		if response.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", response.Code, http.StatusBadRequest)
		}
		if len(results) != 0 {
			t.Error("incomplete callback completed the flow")
		}
	})

	t.Run("duplicate callback does not block", func(t *testing.T) {
		results := make(chan browserCallbackResult, 1)
		handler := newBrowserCallbackHandler(results)
		handler.ServeHTTP(
			httptest.NewRecorder(),
			httptest.NewRequest(http.MethodGet, "/callback?code=first&state=test-state", nil),
		)

		done := make(chan struct{})
		go func() {
			handler.ServeHTTP(
				httptest.NewRecorder(),
				httptest.NewRequest(http.MethodGet, "/callback?code=second&state=test-state", nil),
			)
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("duplicate callback blocked")
		}

		result := <-results
		if result.code != "first" {
			t.Errorf("result code = %q, want first", result.code)
		}
	})
}
