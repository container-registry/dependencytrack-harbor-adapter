package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/etc"
)

type Server struct {
	config etc.API
	server *http.Server
}

func NewServer(config etc.API, handler http.Handler) (server *Server, err error) {
	server = &Server{
		config: config,
		server: &http.Server{
			Handler:      handler,
			Addr:         config.Addr,
			ReadTimeout:  config.ReadTimeout,
			WriteTimeout: config.WriteTimeout,
			IdleTimeout:  config.IdleTimeout,
		},
	}

	if config.IsTLSEnabled() {
		server.server.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{
				tls.X25519,
				tls.CurveP256,
			},
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		}

		if len(config.ClientCAs) > 0 {
			certPool := x509.NewCertPool()
			for _, clientCAPath := range config.ClientCAs {
				clientCA, err := os.ReadFile(clientCAPath)
				if err != nil {
					return nil, fmt.Errorf("could not read file %s: %w", clientCAPath, err)
				}
				// AppendCertsFromPEM reports whether it added anything. Ignoring
				// it left an empty pool with RequireAndVerifyClientCert, which
				// rejects every client certificate -- a total outage presenting
				// as a per-client TLS error.
				if !certPool.AppendCertsFromPEM(clientCA) {
					return nil, fmt.Errorf("client CA file %s contains no usable certificate", clientCAPath)
				}
			}
			server.server.TLSConfig.ClientCAs = certPool
			server.server.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}

	return
}

// ListenAndServe serves in a goroutine and reports how listening ended on the
// returned channel: nil after a graceful Shutdown, the underlying error
// otherwise (bind failure, unreadable TLS material). The error is returned
// rather than os.Exit'd here so the caller decides how to fail — a library
// package exiting the process hid bind and certificate errors from main and
// skipped its cleanup path.
func (s *Server) ListenAndServe() <-chan error {
	result := make(chan error, 1)
	go func() {
		err := s.listenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			slog.Debug("API server stopped listening for incoming connections")
			result <- nil
			return
		}
		result <- err
	}()
	return result
}

func (s *Server) listenAndServe() error {
	if s.config.IsTLSEnabled() {
		slog.Info("Starting API server with TLS", slog.String("addr", s.config.Addr))
		return s.server.ListenAndServeTLS(s.config.TLSCertificate, s.config.TLSKey)
	}
	slog.Warn("Starting API server without TLS", slog.String("addr", s.config.Addr))
	return s.server.ListenAndServe()
}

// shutdownTimeout bounds the graceful drain. http.Server.Shutdown blocks until
// every connection goes idle, so an unbounded context lets one stalled client
// hold the process open — and the signal handler runs Shutdown before stopping
// the worker and closing Redis, so those never get to run either. The container
// would then sit there until the orchestrator escalates to SIGKILL.
const shutdownTimeout = 10 * time.Second

func (s *Server) Shutdown() {
	slog.Debug("API server shutdown started")
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := s.server.Shutdown(ctx); err != nil {
		slog.Error("Error while shutting down API server", slog.String("err", err.Error()))
	}
	slog.Debug("API server shutdown completed")
}
