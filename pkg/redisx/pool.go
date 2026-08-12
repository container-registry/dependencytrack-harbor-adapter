// Package redisx constructs a go-redis client from the SCANNER_REDIS_URL config,
// ported from harbor-scanner-trivy (standalone + sentinel URL schemes).
package redisx

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"

	"github.com/redis/go-redis/v9"
	"golang.org/x/xerrors"

	"github.com/container-registry/waybill-harbor-adapter/pkg/etc"
)

// NewClient constructs a redis.Client from the configured URL.
func NewClient(config etc.RedisPool) (*redis.Client, error) {
	configURL, err := url.Parse(config.URL)
	if err != nil {
		return nil, xerrors.Errorf("invalid redis URL: %s", err)
	}

	switch configURL.Scheme {
	case "redis", "rediss":
		return newInstancePool(config)
	case "redis+sentinel", "rediss+sentinel":
		return newSentinelPool(configURL, config)
	default:
		return nil, xerrors.Errorf("invalid redis URL scheme: %s", configURL.Scheme)
	}
}

func newInstancePool(config etc.RedisPool) (*redis.Client, error) {
	config.URL = strings.ReplaceAll(config.URL, "idle_timeout_seconds=", "idle_timeout=")

	options, err := redis.ParseURL(config.URL)
	if err != nil {
		return nil, xerrors.Errorf("invalid redis URL: %s", err)
	}

	options.MaxIdleConns = config.MaxIdle
	options.MaxActiveConns = config.MaxActive
	options.ConnMaxIdleTime = config.IdleTimeout
	// SCANNER_REDIS_POOL_*_TIMEOUT is the documented contract and supersedes any
	// timeout query params in the URL, matching newSentinelPool. Without this the
	// production redis:// scheme silently fell back to go-redis defaults.
	options.DialTimeout = config.ConnectionTimeout
	options.ReadTimeout = config.ReadTimeout
	options.WriteTimeout = config.WriteTimeout
	options.OnConnect = func(_ context.Context, cn *redis.Conn) error {
		slog.Debug("Connecting to Redis", slog.String("connection", cn.String()))
		return nil
	}

	return redis.NewClient(options), nil
}

func newSentinelPool(configURL *url.URL, config etc.RedisPool) (*redis.Client, error) {
	sentinelURL, err := ParseSentinelURL(configURL)
	if err != nil {
		return nil, xerrors.Errorf("invalid redis sentinel URL: %s", err)
	}

	return redis.NewFailoverClient(&redis.FailoverOptions{
		MasterName:    sentinelURL.MonitorName,
		SentinelAddrs: sentinelURL.Addrs,
		DB:            sentinelURL.Database,
		Password:      sentinelURL.Password,
		Username:      sentinelURL.Username,
		// Sentinel processes have their own AUTH, usually distinct from the
		// master's (and often absent), so the URL credentials are NOT mirrored
		// here: go-redis sends AUTH to a sentinel whenever SentinelPassword is
		// set, and an un-authed sentinel rejects that. Deployments with authed
		// sentinels opt in via ?sentinel_username=...&sentinel_password=....
		SentinelUsername: sentinelURL.SentinelUsername,
		SentinelPassword: sentinelURL.SentinelPassword,

		DialTimeout:  config.ConnectionTimeout,
		ReadTimeout:  config.ReadTimeout,
		WriteTimeout: config.WriteTimeout,

		MaxIdleConns: config.MaxIdle,
		// Same cap as the standalone path: without it a sentinel-backed
		// deployment ignored SCANNER_REDIS_POOL_MAX_ACTIVE entirely.
		MaxActiveConns:  config.MaxActive,
		ConnMaxIdleTime: config.IdleTimeout,

		OnConnect: func(_ context.Context, cn *redis.Conn) error {
			slog.Debug("Connecting to Redis sentinel", slog.String("connection", cn.String()))
			return nil
		},
		TLSConfig: getTLSconfig(configURL),
	}), nil
}

type SentinelURL struct {
	Password    string
	Username    string
	Addrs       []string
	MonitorName string
	Database    int
	// SentinelUsername/SentinelPassword authenticate to the sentinel processes
	// themselves (distinct from the master credentials in the userinfo part).
	// Set via ?sentinel_username=...&sentinel_password=... query parameters.
	SentinelUsername string
	SentinelPassword string
}

func getTLSconfig(configURL *url.URL) *tls.Config {
	if configURL.Scheme == "rediss+sentinel" {
		return &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return nil
}

func ParseSentinelURL(configURL *url.URL) (sentinelURL SentinelURL, err error) {
	ps := strings.Split(configURL.Path, "/")
	if len(ps) < 2 {
		return sentinelURL, fmt.Errorf("invalid redis sentinel URL: no master name")
	}

	if user := configURL.User; user != nil {
		sentinelURL.Username = user.Username()
		if password, set := user.Password(); set {
			sentinelURL.Password = password
		}
	}

	sentinelURL.Addrs = strings.Split(configURL.Host, ",")
	sentinelURL.MonitorName = ps[1]

	query := configURL.Query()
	sentinelURL.SentinelUsername = query.Get("sentinel_username")
	sentinelURL.SentinelPassword = query.Get("sentinel_password")

	if len(ps) > 2 {
		sentinelURL.Database, err = strconv.Atoi(ps[2])
		if err != nil {
			return sentinelURL, fmt.Errorf("invalid redis sentinel URL: invalid database number: %s", ps[2])
		}
	}

	return sentinelURL, nil
}
