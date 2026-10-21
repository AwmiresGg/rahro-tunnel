// Command rahro-node is the agent for a Rahro node. It enrolls to the panel
// with a one-time connection code, then runs as either a location (foreign
// egress) node or a tunnel (Iran relay) node per the config the panel pushes.
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/awmiresgg/rahro/client"
	"github.com/awmiresgg/rahro/core/crypto"
	"github.com/awmiresgg/rahro/core/transport"
	"github.com/awmiresgg/rahro/core/version"
	"github.com/awmiresgg/rahro/internal/config"
	"github.com/awmiresgg/rahro/internal/logx"
	"github.com/awmiresgg/rahro/panel/auth"
	"github.com/awmiresgg/rahro/server"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "rahro-node:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: rahro-node enroll <code> -panel <url> | rahro-node run")
	}
	switch args[0] {
	case "enroll":
		return cmdEnroll(args[1:])
	case "run":
		return cmdRun(args[1:])
	case "version":
		fmt.Println(version.String())
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func httpClient(insecure bool) *http.Client {
	tr := &http.Transport{}
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{Timeout: 20 * time.Second, Transport: tr}
}

func postJSON(c *http.Client, url string, req, resp any) error {
	b, _ := json.Marshal(req)
	r, err := c.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode/100 != 2 {
		var e struct{ Error string }
		json.NewDecoder(r.Body).Decode(&e)
		return fmt.Errorf("panel returned %d: %s", r.StatusCode, e.Error)
	}
	if resp != nil {
		return json.NewDecoder(r.Body).Decode(resp)
	}
	return nil
}

func cmdEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	panelURL := fs.String("panel", "", "panel base URL, e.g. https://panel:2053")
	insecure := fs.Bool("insecure", false, "skip TLS verification (self-signed panel)")
	out := fs.String("out", "rahro-node.json", "where to save node credentials")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) < 1 || *panelURL == "" {
		return fmt.Errorf("usage: rahro-node enroll <code> -panel <url> [-insecure]")
	}
	code := rest[0]

	secret := auth.NewToken(24)
	var resp struct {
		NodeID int64  `json:"node_id"`
		Role   string `json:"role"`
	}
	if err := postJSON(httpClient(*insecure), *panelURL+"/nodeapi/enroll",
		map[string]string{"enroll_token": code, "secret": secret}, &resp); err != nil {
		return err
	}

	local := config.NodeLocalFile{Panel: *panelURL, NodeID: resp.NodeID, Secret: secret, Insecure: *insecure}
	b, _ := json.MarshalIndent(local, "", "  ")
	if err := os.WriteFile(*out, append(b, '\n'), 0o600); err != nil {
		return err
	}
	fmt.Printf("enrolled as node #%d (role %s); credentials saved to %s\n", resp.NodeID, resp.Role, *out)
	fmt.Println("start it with: rahro-node run")
	return nil
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	cfgPath := fs.String("config", "rahro-node.json", "node credentials file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	raw, err := os.ReadFile(*cfgPath)
	if err != nil {
		return fmt.Errorf("read %s (run `rahro-node enroll` first): %w", *cfgPath, err)
	}
	var local config.NodeLocalFile
	if err := json.Unmarshal(raw, &local); err != nil {
		return err
	}

	var dep config.NodeDeploy
	if err := postJSON(httpClient(local.Insecure), local.Panel+"/nodeapi/config",
		map[string]any{"node_id": local.NodeID, "secret": local.Secret}, &dep); err != nil {
		return err
	}

	log := logx.NewDefault("info")
	log.Info("node config pulled", "role", dep.Role, "node_id", dep.NodeID)

	switch dep.Role {
	case "location", "panel":
		return runLocation(dep, log)
	case "tunnel":
		return runTunnel(dep, log)
	default:
		return fmt.Errorf("unknown role %q", dep.Role)
	}
}

func runLocation(dep config.NodeDeploy, log *slog.Logger) error {
	key, err := crypto.PrivateKeyFromBase64(dep.ServerPrivateKey)
	if err != nil {
		return fmt.Errorf("server key: %w", err)
	}
	decoyHost, _, err := net.SplitHostPort(dep.Decoy)
	if err != nil {
		decoyHost = dep.Decoy
	}
	cert, err := transport.GenerateSelfSignedCert(decoyHost)
	if err != nil {
		return err
	}
	tsrv := &transport.TLSServer{
		Key: key, Certificate: cert, Decoy: dep.Decoy,
		Replay: crypto.NewReplayWindow(90 * time.Second), Logger: log,
	}
	ln, err := net.Listen("tcp", dep.Listen)
	if err != nil {
		return err
	}
	l, err := tsrv.NewListener(ln)
	if err != nil {
		return err
	}
	defer l.Close()
	eg := &server.Egress{Log: log}
	log.Info("location node listening (egress)", "listen", dep.Listen, "decoy", dep.Decoy)
	return serveUntilSignal(func() error { return eg.Serve(l) })
}

func runTunnel(dep config.NodeDeploy, log *slog.Logger) error {
	pub, err := crypto.PublicKeyFromBase64(dep.ServerPublicKey)
	if err != nil {
		return fmt.Errorf("upstream public key: %w", err)
	}
	var uid [16]byte
	b, err := hex.DecodeString(dep.UUID)
	if err != nil || len(b) != 16 {
		return fmt.Errorf("bad uuid")
	}
	copy(uid[:], b)

	tc := &transport.TLSClient{
		ServerAddr:  dep.UpstreamAddr,
		SNI:         dep.SNI,
		ServerPub:   pub,
		UserID:      uid,
		Fingerprint: dep.Fingerprint,
	}
	c := client.New(tc, log)
	defer c.Close()
	socks := &client.SOCKS5{Addr: dep.SOCKS, Client: c, Log: log}
	log.Info("tunnel node relaying to upstream", "upstream", dep.UpstreamAddr, "socks", dep.SOCKS)
	return serveUntilSignal(socks.ListenAndServe)
}

func serveUntilSignal(serve func() error) error {
	errc := make(chan error, 1)
	go func() { errc <- serve() }()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-errc:
		return err
	case <-sig:
		return nil
	}
}
