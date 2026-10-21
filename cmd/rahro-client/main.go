// Command rahro-client is the user-side client: it runs local SOCKS5/HTTP
// inbounds and tunnels their traffic to a Rahro server.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/awmiresgg/rahro/client"
	"github.com/awmiresgg/rahro/core/crypto"
	"github.com/awmiresgg/rahro/core/transport"
	"github.com/awmiresgg/rahro/core/version"
	"github.com/awmiresgg/rahro/internal/config"
	"github.com/awmiresgg/rahro/internal/logx"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "rahro-client:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("rahro-client", flag.ContinueOnError)
	configPath := fs.String("config", "rahro-client.json", "path to config file")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Println(version.String())
		return nil
	}

	cfg, err := config.LoadOrDefault(*configPath)
	if err != nil {
		return err
	}
	log := logx.New(logx.Options{Level: cfg.LogLevel, Format: logx.Format(cfg.LogFormat)})
	if cfg.Client == nil {
		return fmt.Errorf("config %q has no [client] section", *configPath)
	}

	serverPub, err := crypto.PublicKeyFromBase64(cfg.Client.PublicKey)
	if err != nil {
		return fmt.Errorf("parse server public key: %w", err)
	}
	uid, err := cfg.Client.UserID()
	if err != nil {
		return err
	}
	sni := cfg.Client.SNI
	if sni == "" {
		if h, _, e := net.SplitHostPort(cfg.Client.Server); e == nil {
			sni = h
		}
	}

	tc := &transport.TLSClient{
		ServerAddr: cfg.Client.Server,
		SNI:        sni,
		ServerPub:  serverPub,
		UserID:     uid,
	}
	c := client.New(tc, log)
	defer c.Close()

	errc := make(chan error, 2)
	if cfg.Client.SOCKS != "" {
		s := &client.SOCKS5{Addr: cfg.Client.SOCKS, Client: c, Log: log}
		go func() { errc <- fmt.Errorf("socks5: %w", s.ListenAndServe()) }()
		log.Info("socks5 inbound", "addr", cfg.Client.SOCKS)
	}
	if cfg.Client.HTTP != "" {
		p := &client.HTTPProxy{Addr: cfg.Client.HTTP, Client: c, Log: log}
		go func() { errc <- fmt.Errorf("http: %w", p.ListenAndServe()) }()
		log.Info("http proxy inbound", "addr", cfg.Client.HTTP)
	}
	log.Info("rahro-client started", "version", version.Version, "server", cfg.Client.Server)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-errc:
		return err
	case s := <-sig:
		log.Info("shutting down", "signal", s.String())
		return nil
	}
}
