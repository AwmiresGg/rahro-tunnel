// Command rahro-server is the tunnel server (VPS side). At M0 it wires up
// configuration, logging, and version reporting; the accept/egress loops and
// the REALITY fallback are added in M3–M4.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/awmiresgg/rahro/core/version"
	"github.com/awmiresgg/rahro/internal/config"
	"github.com/awmiresgg/rahro/internal/logx"
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

	if cfg.Server == nil {
		return fmt.Errorf("config %q has no [server] section", *configPath)
	}
	log.Info("rahro-server starting",
		"version", version.Version,
		"listen", cfg.Server.Listen,
		"transport", cfg.Server.Transport,
		"decoy", cfg.Server.Reality.Decoy,
	)

	// M0: configuration & logging are wired. The accept loop lands in M3.
	log.Warn("tunnel accept loop not yet implemented (arrives in M3); exiting cleanly")
	return nil
}
