package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/awmiresgg/rahro/core/version"
	"github.com/awmiresgg/rahro/internal/config"
	"github.com/awmiresgg/rahro/panel/auth"
	"github.com/awmiresgg/rahro/panel/store"
)

const updateBaseURL = "https://raw.githubusercontent.com/AwmiresGg/rahro-tunnel/HEAD/bin/linux-"

var stdin = bufio.NewReader(os.Stdin)

// cmdMenu runs the interactive x-ui-style management menu.
func cmdMenu(configPath string) error {
	for {
		cfg, err := config.LoadOrDefault(configPath)
		if err != nil {
			return err
		}
		if cfg.Panel == nil {
			cfg.Panel = config.Default().Panel
		}
		printMenu(cfg.Panel)
		switch strings.TrimSpace(ask("Choice")) {
		case "1":
			menuStatus(cfg.Panel)
		case "2":
			svc("restart")
		case "3":
			svc("start")
		case "4":
			svc("stop")
		case "5":
			menuChangeAdmin(cfg.Panel)
		case "6":
			menuChangePort(configPath, cfg)
		case "7":
			menuAccessMode(configPath, cfg)
		case "8":
			menuSecretPath(configPath, cfg)
		case "9":
			menuPublicURL(configPath, cfg)
		case "10":
			menuLogs()
		case "11":
			menuUpdate()
		case "12":
			menuLogin(cfg.Panel)
		case "13":
			if menuUninstall(configPath) {
				return nil
			}
		case "0", "q", "exit":
			return nil
		default:
			fmt.Println("  unknown choice")
		}
		fmt.Println()
	}
}

func printMenu(p *config.PanelConfig) {
	active := svcActive()
	state := "stopped/unknown"
	if active {
		state = "running"
	}
	fmt.Printf("\n\033[36m Rahro panel management \033[0m  (%s · %s)\n", version.Version, state)
	fmt.Println(" ───────────────────────────────")
	fmt.Println("  1) Status & info")
	fmt.Println("  2) Restart panel        3) Start        4) Stop")
	fmt.Println("  5) Change admin username & password")
	fmt.Println("  6) Change panel port")
	fmt.Println("  7) SSL / access mode (self-signed | http | domain+Let's Encrypt)")
	fmt.Println("  8) Set secret path      9) Set public URL")
	fmt.Println(" 10) View recent logs    11) Update panel")
	fmt.Println(" 12) Show login info     13) Uninstall")
	fmt.Println("  0) Exit")
}

// --- actions ---

func menuStatus(p *config.PanelConfig) {
	fmt.Printf("  listen:     %s\n", p.Listen)
	fmt.Printf("  tls_mode:   %s\n", p.TLSMode)
	if p.Domain != "" {
		fmt.Printf("  domain:     %s\n", p.Domain)
	}
	fmt.Printf("  public_url: %s%s\n", strings.TrimRight(p.PublicURL, "/"), p.BasePath)
	fmt.Printf("  service:    %s\n", map[bool]string{true: "running", false: "stopped"}[svcActive()])
}

func menuChangeAdmin(p *config.PanelConfig) {
	st, err := openDB(p)
	if err != nil {
		fmt.Println("  error:", err)
		return
	}
	defer st.Close()
	admin, err := st.FirstAdmin()
	if err != nil {
		fmt.Println("  no admin found; create one with: rahro-panel admin create -u <u> -p <p>")
		return
	}
	newUser := strings.TrimSpace(askDefault("New username", admin.Username))
	newPass := strings.TrimSpace(ask("New password (blank = keep)"))
	hash := admin.PasswordHash
	if newPass != "" {
		if len(newPass) < 6 {
			fmt.Println("  password must be at least 6 characters")
			return
		}
		hash, _ = auth.HashPassword(newPass)
	}
	if err := st.UpdateAdminCredentials(admin.ID, newUser, hash); err != nil {
		fmt.Println("  error:", err)
		return
	}
	fmt.Println("  ✓ admin updated. Restart not required (takes effect on next login).")
}

func menuChangePort(configPath string, cfg *config.Config) {
	host, _, _ := net.SplitHostPort(cfg.Panel.Listen)
	cur := portOf(cfg.Panel.Listen)
	ns := strings.TrimSpace(askDefault("New panel port", cur))
	n, err := strconv.Atoi(ns)
	if err != nil || n < 1 || n > 65535 {
		fmt.Println("  invalid port")
		return
	}
	if host == "" {
		host = "0.0.0.0"
	}
	cfg.Panel.Listen = net.JoinHostPort(host, ns)
	cfg.Panel.PublicURL = swapURLPort(cfg.Panel.PublicURL, ns)
	saveAndRestart(configPath, cfg, fmt.Sprintf("port set to %d", n))
}

func menuAccessMode(configPath string, cfg *config.Config) {
	fmt.Println("  1) IP + self-signed TLS   2) IP over HTTP   3) Domain + Let's Encrypt")
	switch strings.TrimSpace(ask("Mode")) {
	case "1":
		cfg.Panel.TLSMode = config.PanelTLSSelfSigned
		cfg.Panel.Domain = ""
		cfg.Panel.PublicURL = setScheme(cfg.Panel.PublicURL, "https")
	case "2":
		cfg.Panel.TLSMode = config.PanelTLSOff
		cfg.Panel.Domain = ""
		cfg.Panel.PublicURL = setScheme(cfg.Panel.PublicURL, "http")
	case "3":
		d := strings.TrimSpace(ask("Domain (A record must point here; ports 80+443 open)"))
		if d == "" {
			fmt.Println("  domain required")
			return
		}
		cfg.Panel.TLSMode = config.PanelTLSDomain
		cfg.Panel.Domain = d
		cfg.Panel.PublicURL = fmt.Sprintf("https://%s:%s", d, portOf(cfg.Panel.Listen))
		fmt.Println("  Let's Encrypt cert is fetched automatically on restart.")
	default:
		fmt.Println("  cancelled")
		return
	}
	saveAndRestart(configPath, cfg, "access mode updated")
}

func menuSecretPath(configPath string, cfg *config.Config) {
	bp := strings.TrimSpace(ask("Secret path (e.g. /x7f3a9, blank to clear)"))
	if bp != "" && !strings.HasPrefix(bp, "/") {
		bp = "/" + bp
	}
	cfg.Panel.BasePath = bp
	saveAndRestart(configPath, cfg, "secret path updated")
}

func menuPublicURL(configPath string, cfg *config.Config) {
	u := strings.TrimSpace(askDefault("Public URL", cfg.Panel.PublicURL))
	cfg.Panel.PublicURL = u
	saveAndRestart(configPath, cfg, "public URL updated")
}

func menuLogs() {
	if !hasSystemctl() {
		fmt.Println("  systemd not available; check your own supervisor's logs")
		return
	}
	runCmd("journalctl", "-u", "rahro-panel", "-n", "80", "--no-pager")
}

const updateRepo = "AwmiresGg/rahro-tunnel"
const updateBranch = "vpn-tunnel-panel-RAHR0"

func menuUpdate() {
	arch := runtime.GOARCH
	// raw.githubusercontent.com is edge-cached per region, so a plain HEAD URL
	// can serve a stale binary long after a push. Resolve the latest commit SHA
	// (immutable path -> never stale); fall back to HEAD with a cache-buster.
	ref := "HEAD"
	if sha, err := latestSHA(updateBranch); err == nil && len(sha) >= 7 {
		ref = sha
	}
	url := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/bin/linux-%s/rahro-panel?t=%d",
		updateRepo, ref, arch, time.Now().UnixNano())
	fmt.Printf("  downloading latest rahro-panel (%s, ref %.12s) …\n", arch, ref)
	dst := selfPath()
	if err := downloadTo(url, dst); err != nil {
		fmt.Println("  update failed:", err)
		fmt.Println("  (if it says permission denied, run the menu with sudo: sudo rahro)")
		return
	}
	// Report the version actually on disk now, so a cached/failed download is
	// obvious instead of silent.
	out, _ := exec.Command(dst, "version").Output()
	fmt.Printf("  ✓ updated to: %s", out)
	if v := strings.TrimSpace(string(out)); v != "" && !strings.Contains(v, version.Version) {
		fmt.Println("  (new binary installed; restarting the service)")
	}
	fmt.Println("  restarting …")
	svc("restart")
}

// latestSHA returns the newest commit SHA of a branch via the GitHub API. The
// vnd.github.sha media type returns just the hex SHA, nothing else.
func latestSHA(branch string) (string, error) {
	req, err := http.NewRequest(http.MethodGet,
		"https://api.github.com/repos/"+updateRepo+"/commits/"+branch, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github.sha")
	req.Header.Set("User-Agent", "rahro-updater")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 100))
	sha := strings.TrimSpace(string(b))
	for _, c := range sha {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return "", fmt.Errorf("unexpected sha %q", sha)
		}
	}
	return sha, nil
}

// selfPath returns the path of the running rahro-panel binary (falls back to
// the conventional install path).
func selfPath() string {
	if p, err := os.Executable(); err == nil && p != "" {
		return p
	}
	return "/usr/local/bin/rahro-panel"
}

func menuLogin(p *config.PanelConfig) {
	st, err := openDB(p)
	if err == nil {
		defer st.Close()
		if a, e := st.FirstAdmin(); e == nil {
			fmt.Printf("  admin username: %s\n", a.Username)
		}
	}
	fmt.Printf("  panel URL:      %s%s\n", strings.TrimRight(p.PublicURL, "/"), p.BasePath)
	fmt.Println("  (password is not stored in clear text — use option 5 to set a new one)")
}

func menuUninstall(configPath string) bool {
	if strings.ToLower(strings.TrimSpace(ask("Type 'yes' to uninstall the panel"))) != "yes" {
		fmt.Println("  cancelled")
		return false
	}
	if hasSystemctl() {
		runCmd("systemctl", "disable", "--now", "rahro-panel")
		os.Remove("/etc/systemd/system/rahro-panel.service")
		runCmd("systemctl", "daemon-reload")
	}
	os.Remove("/usr/local/bin/rahro-panel")
	os.Remove("/usr/local/bin/rahro")
	fmt.Println("  ✓ panel removed. Config and DB kept at /etc/rahro (delete manually if desired).")
	return true
}

// --- helpers ---

func ask(label string) string {
	fmt.Printf("  %s: ", label)
	line, _ := stdin.ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}

func askDefault(label, def string) string {
	v := ask(fmt.Sprintf("%s [%s]", label, def))
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func openDB(p *config.PanelConfig) (*store.Store, error) {
	db := p.DBPath
	if db == "" {
		db = "rahro-panel.db"
	}
	return store.Open(db)
}

func saveAndRestart(configPath string, cfg *config.Config, msg string) {
	if err := cfg.Save(configPath); err != nil {
		fmt.Println("  error saving config:", err)
		return
	}
	fmt.Println("  ✓", msg)
	svc("restart")
}

func svc(action string) {
	if !hasSystemctl() {
		fmt.Printf("  systemd not available; please %s the panel with your own supervisor\n", action)
		return
	}
	if err := runCmd("systemctl", action, "rahro-panel"); err == nil {
		fmt.Printf("  ✓ panel %sed\n", strings.TrimSuffix(action, "t"))
	}
}

func svcActive() bool {
	if !hasSystemctl() {
		return false
	}
	return exec.Command("systemctl", "is-active", "--quiet", "rahro-panel").Run() == nil
}

func hasSystemctl() bool {
	_, err := exec.LookPath("systemctl")
	return err == nil
}

func runCmd(name string, args ...string) error {
	c := exec.Command(name, args...)
	c.Stdout, c.Stderr, c.Stdin = os.Stdout, os.Stderr, os.Stdin
	return c.Run()
}

func downloadTo(rawURL, dst string) error {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	tmp := dst + ".new"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	f.Close()
	return os.Rename(tmp, dst)
}

func setScheme(rawURL, scheme string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return rawURL
	}
	u.Scheme = scheme
	return u.String()
}

func swapURLPort(rawURL, port string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return rawURL
	}
	host := u.Hostname()
	u.Host = net.JoinHostPort(host, port)
	return u.String()
}

func portOf(listen string) string {
	if _, p, err := net.SplitHostPort(listen); err == nil {
		return p
	}
	return ""
}
