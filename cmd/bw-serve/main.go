// Command bw-serve is a lightweight Go reimplementation of `bw serve`
// (the Bitwarden CLI Vault Management API).
package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/liamniou/bitwarden-rest-api-server-go/internal/api"
	"github.com/liamniou/bitwarden-rest-api-server-go/internal/server"
	"github.com/liamniou/bitwarden-rest-api-server-go/internal/vault"
)

var version = "dev"

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envBool(key string) bool {
	v := strings.ToLower(os.Getenv(key))
	return v == "1" || v == "true" || v == "yes"
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck())
	}
	if len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		fmt.Println(version)
		return
	}

	defPort, _ := strconv.Atoi(env("BW_SERVE_PORT", "8087"))
	hostname := flag.String("hostname", env("BW_SERVE_HOSTNAME", "all"), "hostname to bind (\"all\" for every interface)")
	port := flag.Int("port", defPort, "port to listen on")
	disableOrigin := flag.Bool("disable-origin-protection", envBool("BW_DISABLE_ORIGIN_PROTECTION"), "allow requests with an Origin header")
	flag.Parse()

	level := slog.LevelInfo
	switch strings.ToLower(env("LOG_LEVEL", "info")) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	urls := api.ResolveURLs(env("BW_HOST", "https://vault.bitwarden.com"), os.Getenv("BW_API_URL"), os.Getenv("BW_IDENTITY_URL"))
	dataDir := env("BITWARDENCLI_APPDATA_DIR", "/data")
	client := api.NewClient(urls, deviceID(dataDir, log))
	v := vault.New(client, log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	syncInterval := 120 * time.Second
	if s := os.Getenv("VAULT_SYNC_INTERVAL"); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			syncInterval = time.Duration(n) * time.Second
		}
	}
	go bootstrap(ctx, v, log, syncInterval, envBool("VAULT_SYNC_FORCE"))

	srv := server.New(v, server.Options{Hostname: *hostname, Port: *port, DisableOriginProtection: *disableOrigin, Logger: log})
	bind := ""
	if *hostname != "all" {
		bind = *hostname
	}
	httpSrv := &http.Server{
		Addr:              net.JoinHostPort(bind, strconv.Itoa(*port)),
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 30 * time.Second,
	}
	protection := "origin protection"
	if *disableOrigin {
		protection = "no origin protection"
	}
	log.Info(fmt.Sprintf("Starting server on %s:%d with %s", *hostname, *port, protection), "version", version)
	errCh := make(chan error, 1)
	go func() { errCh <- httpSrv.ListenAndServe() }()

	select {
	case <-ctx.Done():
		log.Info("Shutting down gracefully...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
		v.Lock()
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server failed", "err", err)
			os.Exit(1)
		}
	}
}

// bootstrap logs in, unlocks and keeps the vault in sync, retrying on failure.
func bootstrap(ctx context.Context, v *vault.Vault, log *slog.Logger, interval time.Duration, force bool) {
	clientID, clientSecret := os.Getenv("BW_CLIENTID"), os.Getenv("BW_CLIENTSECRET")
	user, password := os.Getenv("BW_USER"), os.Getenv("BW_PASSWORD")

	backoff := 5 * time.Second
	for {
		var err error
		switch {
		case clientID != "" && clientSecret != "":
			log.Info("Using apikey to log in")
			err = v.LoginAPIKey(ctx, clientID, clientSecret)
		case user != "" && password != "":
			log.Info("Using username and password to log in")
			err = v.LoginPassword(ctx, user, password, os.Getenv("BW_TWO_FACTOR_TOKEN"), env("BW_TWO_FACTOR_METHOD", "0"))
		default:
			log.Error("no credentials: set BW_CLIENTID/BW_CLIENTSECRET (recommended) or BW_USER, plus BW_PASSWORD")
			return
		}
		if err == nil {
			break
		}
		log.Error("login failed", "err", err, "retry_in", backoff)
		if !sleep(ctx, backoff) {
			return
		}
		backoff = min(backoff*2, 5*time.Minute)
	}

	backoff = 5 * time.Second
	for {
		err := v.Sync(ctx, true)
		if err == nil {
			break
		}
		log.Error("initial sync failed", "err", err, "retry_in", backoff)
		if !sleep(ctx, backoff) {
			return
		}
		backoff = min(backoff*2, 5*time.Minute)
	}

	if password != "" {
		log.Info("Unlocking vault")
		if err := v.Unlock(password); err != nil {
			log.Error("unlock failed; vault stays locked until POST /unlock", "err", err)
		} else {
			log.Info("Vault unlocked", "items", len(v.Ciphers()))
		}
	} else {
		log.Warn("BW_PASSWORD not set; vault stays locked until POST /unlock")
	}

	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			if err := v.Sync(sctx, force); err != nil {
				log.Warn("background sync failed", "err", err)
			} else {
				log.Debug("background sync complete")
			}
			cancel()
		}
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// deviceID returns a stable device identifier so restarts don't register new devices.
// It reuses the official CLI's appId from data.json when migrating an existing volume.
func deviceID(dir string, log *slog.Logger) string {
	path := filepath.Join(dir, "go-device-id")
	if b, err := os.ReadFile(path); err == nil {
		if id := strings.TrimSpace(string(b)); id != "" {
			return id
		}
	}
	id := ""
	if b, err := os.ReadFile(filepath.Join(dir, "data.json")); err == nil {
		var m map[string]any
		if json.Unmarshal(b, &m) == nil {
			if s, ok := m["global_applicationId_appId"].(string); ok {
				id = s
			} else if s, ok := m["appId"].(string); ok {
				id = s
			}
		}
	}
	if id == "" {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		b[6] = (b[6] & 0x0f) | 0x40
		b[8] = (b[8] & 0x3f) | 0x80
		id = fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
	}
	if err := os.MkdirAll(dir, 0o700); err == nil {
		if err := os.WriteFile(path, []byte(id), 0o600); err != nil {
			log.Warn("could not persist device id; a new device will be registered on every restart", "err", err)
		}
	}
	return id
}

// healthcheck exits 0 when /status reports an unlocked vault.
func healthcheck() int {
	port := env("BW_SERVE_PORT", "8087")
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://127.0.0.1:" + port + "/status")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var r struct {
		Success bool `json:"success"`
		Data    struct {
			Template struct {
				Status string `json:"status"`
			} `json:"template"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &r) != nil || !r.Success || r.Data.Template.Status != "unlocked" {
		fmt.Fprintln(os.Stderr, string(body))
		return 1
	}
	return 0
}
