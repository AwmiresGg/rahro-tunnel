package e2e

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/net/proxy"

	"github.com/awmiresgg/rahro/client"
	"github.com/awmiresgg/rahro/core/crypto"
	"github.com/awmiresgg/rahro/core/transport"
	"github.com/awmiresgg/rahro/internal/config"
	"github.com/awmiresgg/rahro/panel/api"
	"github.com/awmiresgg/rahro/panel/auth"
	"github.com/awmiresgg/rahro/panel/store"
	"github.com/awmiresgg/rahro/server"
)

// TestNodeControlPlaneToDataPlane ties M8 (panel issues node config via
// enrollment) to M9 (tunnel node relays to a location node over the Rahro
// tunnel): a location node runs the Rahro server with the panel-issued private
// key, a tunnel node connects with the panel-issued public key, and real HTTP
// traffic flows through to an origin.
func TestNodeControlPlaneToDataPlane(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	hash, _ := auth.HashPassword("pw")
	st.CreateAdmin("admin", hash)

	panelSrv := httptest.NewServer(api.New(st, nil, "http://panel.test").Routes())
	t.Cleanup(panelSrv.Close)

	jar, _ := cookiejar.New(nil)
	ac := &http.Client{Jar: jar}
	must2xx(t, ac, "POST", panelSrv.URL+"/api/login", `{"username":"admin","password":"pw"}`, nil)

	// 1) Create + enroll a LOCATION node; pull its config (server private key).
	locCode := createNode(t, ac, panelSrv.URL, `{"name":"nl-1","role":"location","location":"NL","address":"placeholder:443"}`)
	locDep := enrollAndConfig(t, panelSrv.URL, locCode)
	if locDep.ServerPrivateKey == "" {
		t.Fatal("location node config missing server private key")
	}

	// 2) Start the location node's Rahro server with that key.
	key, err := crypto.PrivateKeyFromBase64(locDep.ServerPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := transport.GenerateSelfSignedCert("www.microsoft.com", "127.0.0.1")
	tsrv := &transport.TLSServer{
		Key: key, Certificate: cert, Decoy: "example.invalid:443",
		Replay: crypto.NewReplayWindow(90 * time.Second),
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	l, err := tsrv.NewListener(ln)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go (&server.Egress{}).Serve(l)
	locAddr := l.Addr().String()

	// 3) Create + enroll a TUNNEL node pointing upstream at the location node.
	tunCode := createNode(t, ac, panelSrv.URL,
		fmt.Sprintf(`{"name":"tehran-1","role":"tunnel","location":"IR","upstream":%q}`, locAddr))
	tunDep := enrollAndConfig(t, panelSrv.URL, tunCode)
	if tunDep.ServerPublicKey == "" || tunDep.UpstreamAddr != locAddr {
		t.Fatalf("tunnel config wrong: %+v", tunDep)
	}

	// 4) Start the tunnel node: Rahro client to the location + local SOCKS5.
	pub, err := crypto.PublicKeyFromBase64(tunDep.ServerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var uid [16]byte
	b, _ := hex.DecodeString(tunDep.UUID)
	copy(uid[:], b)
	tc := &transport.TLSClient{ServerAddr: locAddr, SNI: tunDep.SNI, ServerPub: pub, UserID: uid}
	c := client.New(tc, nil)
	t.Cleanup(func() { c.Close() })
	socksLn, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { socksLn.Close() })
	go (&client.SOCKS5{Client: c}).Serve(socksLn)

	// 5) Real traffic: user -> tunnel node -> Rahro tunnel -> location egress -> origin.
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ORIGIN-OK")
	}))
	defer origin.Close()

	dialer, _ := proxy.SOCKS5("tcp", socksLn.Addr().String(), nil, proxy.Direct)
	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(_ context.Context, n, a string) (net.Conn, error) { return dialer.Dial(n, a) },
	}}
	resp, err := hc.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "ORIGIN-OK" {
		t.Fatalf("got %q through the node tunnel, want ORIGIN-OK", body)
	}
}

// --- helpers ---

func must2xx(t *testing.T, c *http.Client, method, url, body string, out any) {
	t.Helper()
	req, _ := http.NewRequest(method, url, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("%s %s -> %d: %s", method, url, resp.StatusCode, b)
	}
	if out != nil {
		json.NewDecoder(resp.Body).Decode(out)
	}
}

// createNode creates a node via the admin API and returns its enrollment code.
func createNode(t *testing.T, c *http.Client, panelURL, body string) string {
	t.Helper()
	var resp struct {
		ConnectionCode string `json:"connection_code"`
	}
	must2xx(t, c, "POST", panelURL+"/api/nodes", body, &resp)
	if resp.ConnectionCode == "" {
		t.Fatal("no connection code returned")
	}
	return resp.ConnectionCode
}

// enrollAndConfig performs the node-side enroll + config pull.
func enrollAndConfig(t *testing.T, panelURL, code string) config.NodeDeploy {
	t.Helper()
	secret := auth.NewToken(24)
	nc := &http.Client{}

	var en struct {
		NodeID int64 `json:"node_id"`
	}
	must2xx(t, nc, "POST", panelURL+"/nodeapi/enroll",
		fmt.Sprintf(`{"enroll_token":%q,"secret":%q}`, code, secret), &en)

	var dep config.NodeDeploy
	must2xx(t, nc, "POST", panelURL+"/nodeapi/config",
		fmt.Sprintf(`{"node_id":%d,"secret":%q}`, en.NodeID, secret), &dep)
	return dep
}
