// Command rahro-client is the user-side client. At M0 it wires up configuration,
// logging, and version reporting; the local SOCKS/HTTP inbounds and the dial
// path are added in M4.
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
	log.Info("rahro-client starting",
		"version", version.Version,
		"server", cfg.Client.Server,
		"transport", cfg.Client.Transport,
		"socks", cfg.Client.SOCKS,
		"http", cfg.Client.HTTP,
	)

	// M0: configuration & logging are wired. The inbounds + dial path land in M4.
	log.Warn("local inbounds not yet implemented (arrive in M4); exiting cleanly")
	return nil
}
