// Command rahro-panel runs the Rahro management panel and its CLI
// (admin/token management), mirroring the ergonomics of 3x-ui / Smite.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/awmiresgg/rahro/core/version"
	"github.com/awmiresgg/rahro/internal/config"
	"github.com/awmiresgg/rahro/internal/logx"
	"github.com/awmiresgg/rahro/panel"
	"github.com/awmiresgg/rahro/panel/auth"
	"github.com/awmiresgg/rahro/panel/store"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "rahro-panel:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cmd := "run"
	if len(args) > 0 && !isFlag(args[0]) {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "run":
		return cmdRun(args)
	case "admin":
		return cmdAdmin(args)
	case "token":
		return cmdToken(args)
	case "menu":
		fs := flag.NewFlagSet("menu", flag.ContinueOnError)
		configPath := fs.String("config", "/etc/rahro/panel.json", "config file")
		if err := fs.Parse(args); err != nil {
			return err
		}
		return cmdMenu(*configPath)
	case "version":
		fmt.Println(version.String())
		return nil
	default:
		return fmt.Errorf("unknown command %q (run|menu|admin|token|version)", cmd)
	}
}

func isFlag(s string) bool { return len(s) > 0 && s[0] == '-' }

func openStore(configPath string) (*store.Store, *config.Config, error) {
	cfg, err := config.LoadOrDefault(configPath)
	if err != nil {
		return nil, nil, err
	}
	if cfg.Panel == nil {
		cfg.Panel = config.Default().Panel
	}
	dbPath := cfg.Panel.DBPath
	if dbPath == "" {
		dbPath = "rahro-panel.db"
	}
	st, err := store.Open(dbPath)
	if err != nil {
		return nil, nil, err
	}
	return st, cfg, nil
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	configPath := fs.String("config", "rahro-panel.json", "config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, cfg, err := openStore(*configPath)
	if err != nil {
		return err
	}
	defer st.Close()
	log := logx.New(logx.Options{Level: cfg.LogLevel, Format: logx.Format(cfg.LogFormat)})

	if n, _ := st.CountAdmins(); n == 0 {
		log.Warn("no admin exists yet — create one with: rahro-panel admin create -u <user> -p <pass>")
	}
	return panel.Run(st, cfg.Panel, log)
}

func cmdAdmin(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: rahro-panel admin create|passwd -u <user> -p <pass>")
	}
	sub := args[0]
	fs := flag.NewFlagSet("admin", flag.ContinueOnError)
	configPath := fs.String("config", "rahro-panel.json", "config file")
	user := fs.String("u", "", "username")
	pass := fs.String("p", "", "password")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *user == "" || *pass == "" {
		return fmt.Errorf("both -u and -p are required")
	}
	st, _, err := openStore(*configPath)
	if err != nil {
		return err
	}
	defer st.Close()

	hash, err := auth.HashPassword(*pass)
	if err != nil {
		return err
	}
	switch sub {
	case "create":
		if _, err := st.CreateAdmin(*user, hash); err != nil {
			return err
		}
		fmt.Printf("admin %q created\n", *user)
	case "passwd":
		if err := st.UpdateAdminPassword(*user, hash); err != nil {
			return err
		}
		fmt.Printf("password updated for %q\n", *user)
	default:
		return fmt.Errorf("unknown admin subcommand %q", sub)
	}
	return nil
}

func cmdToken(args []string) error {
	if len(args) == 0 || args[0] != "create" {
		return fmt.Errorf("usage: rahro-panel token create -name <name>")
	}
	fs := flag.NewFlagSet("token", flag.ContinueOnError)
	configPath := fs.String("config", "rahro-panel.json", "config file")
	name := fs.String("name", "telegram-bot", "token name")
	scopes := fs.String("scopes", "users:write", "token scopes")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	st, _, err := openStore(*configPath)
	if err != nil {
		return err
	}
	defer st.Close()

	plain := auth.NewAPIToken()
	if _, err := st.CreateAPIToken(*name, auth.HashToken(plain), *scopes); err != nil {
		return err
	}
	fmt.Println("API token (shown once):", plain)
	return nil
}
