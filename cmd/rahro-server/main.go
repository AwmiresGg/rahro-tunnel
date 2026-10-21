// Command rahro-server is the tunnel server (VPS side): it terminates the
// Rahro transport, applies the REALITY-style probe defense, and egresses
// authenticated streams to the Internet.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/awmiresgg/rahro/core/crypto"
	"github.com/awmiresgg/rahro/core/transport"
	"github.com/awmiresgg/rahro/core/version"
	"github.com/awmiresgg/rahro/internal/config"
	"github.com/awmiresgg/rahro/internal/logx"
	"github.com/awmiresgg/rahro/server"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "rahro-server:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("rahro-server", flag.ContinueOnError)
	configPath := fs.String("config", "rahro.json", "path to config file")
	showVersion := fs.Bool("version", false, "print version and exit")
	genKey := fs.Bool("genkey", false, "generate an X25519 keypair and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Println(version.String())
		return nil
	}
	if *genKey {
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			return err
		}
		fmt.Println("private_key:", kp.PrivateBase64())
		fmt.Println("public_key: ", kp.PublicBase64())
		return nil
	}

	cfg, err := config.LoadOrDefault(*configPath)
	if err != nil {
		return err
	}
	log := logx.New(logx.Options{Level: cfg.LogLevel, Format: logx.Format(cfg.LogFormat)})
	if cfg.Server == nil {
		return fmt.Errorf("config %q has no [server] section", *configPath)
	}

	// Load or generate the long-term server key.
	var key *crypto.KeyPair
	if cfg.Server.Reality.PrivateKey != "" {
		key, err = crypto.PrivateKeyFromBase64(cfg.Server.Reality.PrivateKey)
		if err != nil {
			return fmt.Errorf("parse server private key: %w", err)
		}
	} else {
		key, err = crypto.GenerateKeyPair()
		if err != nil {
			return err
		}
		cfg.Server.Reality.PrivateKey = key.PrivateBase64()
		if err := cfg.Save(*configPath); err != nil {
			log.Warn("could not persist generated key", "err", err)
		} else {
			log.Info("generated and saved server key", "config", *configPath)
		}
	}
	log.Info("server public key", "public_key", key.PublicBase64())

	// Decoy SNI -> cert host.
	decoyHost, _, err := net.SplitHostPort(cfg.Server.Reality.Decoy)
	if err != nil {
		decoyHost = cfg.Server.Reality.Decoy
	}
	cert, err := transport.GenerateSelfSignedCert(decoyHost)
	if err != nil {
		return fmt.Errorf("generate cert: %w", err)
	}

	tsrv := &transport.TLSServer{
		Key:         key,
		Certificate: cert,
		Decoy:       cfg.Server.Reality.Decoy,
		Replay:      crypto.NewReplayWindow(90 * time.Second),
		Logger:      log,
	}
	ln, err := net.Listen("tcp", cfg.Server.Listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.Server.Listen, err)
	}
	l, err := tsrv.NewListener(ln)
	if err != nil {
		return err
	}
	defer l.Close()

	egress := &server.Egress{Log: log}
	errc := make(chan error, 1)
	go func() { errc <- egress.Serve(l) }()

	log.Info("rahro-server listening",
		"version", version.Version, "listen", cfg.Server.Listen, "decoy", cfg.Server.Reality.Decoy)

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
