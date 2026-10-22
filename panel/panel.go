// Package panel wires the store, API, and embedded SPA into an HTTP(S) server
// with the three reachability modes: IP over HTTP, IP with a self-signed
// certificate, or a domain with an automatic Let's Encrypt certificate.
package panel

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/awmiresgg/rahro/core/transport"
	"github.com/awmiresgg/rahro/internal/config"
	"github.com/awmiresgg/rahro/panel/api"
	"github.com/awmiresgg/rahro/panel/store"
	"github.com/awmiresgg/rahro/panel/web"
	"github.com/awmiresgg/rahro/panel/xray"
)

// Run starts the panel using the given store and config, blocking until the
// server stops.
func Run(st *store.Store, cfg *config.PanelConfig, log *slog.Logger) error {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	publicBase := derivePublicURL(cfg)
	apiSrv := api.New(st, log, publicBase)

	// Managed Xray-core: download in the background, then serve the configured
	// inbounds. Failure (e.g. no network to GitHub) leaves the panel fully
	// usable; inbounds just won't serve until Xray is installed.
	xrayDir := "xray"
	if cfg.DBPath != "" {
		xrayDir = filepath.Join(filepath.Dir(cfg.DBPath), "xray")
	}
	mgr := xray.NewManager(xrayDir, log)
	apiSrv.Xray = mgr
	go func() {
		if err := mgr.EnsureBinary(); err != nil {
			log.Warn("xray-core not installed; inbounds will not serve until it is", "err", err)
			return
		}
		apiSrv.ApplyXray()
	}()

	apiMux := apiSrv.Routes()

	root := http.NewServeMux()
	root.Handle("/api/", apiMux)
	root.Handle("/sub/", apiMux)
	root.Handle("/botapi/", apiMux)
	root.Handle("/nodeapi/", apiMux)
	root.Handle("/", web.Handler())

	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           secureHeaders(root),
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Info("panel starting", "listen", cfg.Listen, "tls", string(cfg.TLSMode), "public_url", publicBase)

	switch cfg.TLSMode {
	case config.PanelTLSOff:
		return httpSrv.ListenAndServe()

	case config.PanelTLSSelfSigned:
		host := hostOf(cfg.Listen)
		hosts := []string{"localhost", "127.0.0.1"}
		if host != "" && host != "0.0.0.0" {
			hosts = append(hosts, host)
		}
		cert, err := transport.GenerateSelfSignedCert(hosts...)
		if err != nil {
			return fmt.Errorf("panel: self-signed cert: %w", err)
		}
		httpSrv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		return httpSrv.ListenAndServeTLS("", "")

	case config.PanelTLSDomain:
		if cfg.CertFile != "" && cfg.KeyFile != "" {
			return httpSrv.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile)
		}
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.Domain),
			Cache:      autocert.DirCache("rahro-acme"),
		}
		httpSrv.TLSConfig = m.TLSConfig()
		// Serve the ACME http-01 challenge on :80.
		go func() {
			_ = http.ListenAndServe(":80", m.HTTPHandler(nil))
		}()
		return httpSrv.ListenAndServeTLS("", "")

	default:
		return fmt.Errorf("panel: unknown tls mode %q", cfg.TLSMode)
	}
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func hostOf(listen string) string {
	if h, _, err := net.SplitHostPort(listen); err == nil {
		return h
	}
	return ""
}

func portOf(listen string) string {
	if _, p, err := net.SplitHostPort(listen); err == nil {
		return p
	}
	return ""
}

// derivePublicURL builds the base URL used for subscription links.
func derivePublicURL(cfg *config.PanelConfig) string {
	if cfg.PublicURL != "" {
		return strings.TrimRight(cfg.PublicURL, "/")
	}
	scheme := "https"
	if cfg.TLSMode == config.PanelTLSOff {
		scheme = "http"
	}
	host := cfg.Domain
	if host == "" {
		host = hostOf(cfg.Listen)
		if host == "" || host == "0.0.0.0" {
			host = "YOUR_SERVER_IP"
		}
	}
	return fmt.Sprintf("%s://%s:%s", scheme, host, portOf(cfg.Listen))
}
