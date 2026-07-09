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

	"github.com/container-registry/mikebom-harbor-adapter/pkg/etc"
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
				certPool.AppendCertsFromPEM(clientCA)
			}
			server.server.TLSConfig.ClientCAs = certPool
			server.server.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}

	return
}

func (s *Server) ListenAndServe() {
	go func() {
		if err := s.listenAndServe(); errors.Is(err, http.ErrServerClosed) {
			slog.Debug("API server stopped listening for incoming connections")
			return
		} else if err != nil {
			slog.Error("API server error", slog.String("err", err.Error()))
			os.Exit(1)
		}
	}()
}

func (s *Server) listenAndServe() error {
	if s.config.IsTLSEnabled() {
		slog.Info("Starting API server with TLS", slog.String("addr", s.config.Addr))
		return s.server.ListenAndServeTLS(s.config.TLSCertificate, s.config.TLSKey)
	}
	slog.Warn("Starting API server without TLS", slog.String("addr", s.config.Addr))
	return s.server.ListenAndServe()
}

func (s *Server) Shutdown() {
	slog.Debug("API server shutdown started")
	if err := s.server.Shutdown(context.Background()); err != nil {
		slog.Error("Error while shutting down API server", slog.String("err", err.Error()))
	}
	slog.Debug("API server shutdown completed")
}
