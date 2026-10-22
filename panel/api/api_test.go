package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/awmiresgg/rahro/panel/auth"
	"github.com/awmiresgg/rahro/panel/store"
)

func setup(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	hash, _ := auth.HashPassword("adminpass")
	st.CreateAdmin("admin", hash)

	srv := New(st, nil, "https://panel.test:2053")
	ts := httptest.NewServer(srv.Routes())
	t.Cleanup(ts.Close)
	return ts, st
}

func TestAdminLoginAndUserCRUD(t *testing.T) {
	ts, _ := setup(t)
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}

	// Unauthenticated access is rejected.
	resp, _ := c.Get(ts.URL + "/api/users")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}

	// Wrong password.
	if code := postJSON(t, c, ts.URL+"/api/login", `{"username":"admin","password":"wrong"}`, nil); code != 401 {
		t.Fatalf("bad login want 401, got %d", code)
	}
	// Correct login sets a cookie.
	if code := postJSON(t, c, ts.URL+"/api/login", `{"username":"admin","password":"adminpass"}`, nil); code != 200 {
		t.Fatalf("login want 200, got %d", code)
	}

	// Create a user.
	var created store.User
	if code := postJSON(t, c, ts.URL+"/api/users", `{"username":"kian","quota_gb":100,"days":30}`, &created); code != 201 {
		t.Fatalf("create user want 201, got %d", code)
	}
	if created.UUID == "" || created.SubToken == "" || created.QuotaBytes != 100*gib {
		t.Fatalf("unexpected user: %+v", created)
	}

	// List shows one user.
	var list []store.User
	getJSON(t, c, ts.URL+"/api/users", &list)
	if len(list) != 1 {
		t.Fatalf("want 1 user, got %d", len(list))
	}

	// Subscription endpoint (public) returns base64 with a config line.
	sresp, _ := http.Get(ts.URL + "/sub/" + created.SubToken)
	body, _ := io.ReadAll(sresp.Body)
	// No nodes yet -> active user, empty config list (valid base64).
	if _, err := base64.StdEncoding.DecodeString(string(body)); err != nil {
		t.Fatalf("subscription body not base64: %v", err)
	}
}

func TestChangeAccount(t *testing.T) {
	ts, st := setup(t)
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	if code := postJSON(t, c, ts.URL+"/api/login", `{"username":"admin","password":"adminpass"}`, nil); code != 200 {
		t.Fatalf("login: %d", code)
	}

	// Wrong current password is rejected.
	if code := postJSON(t, c, ts.URL+"/api/account", `{"current_password":"nope","new_password":"brandnew1"}`, nil); code != 401 {
		t.Fatalf("wrong current password should be 401, got %d", code)
	}
	// Change username + password.
	if code := postJSON(t, c, ts.URL+"/api/account", `{"current_password":"adminpass","new_username":"boss","new_password":"brandnew1"}`, nil); code != 200 {
		t.Fatalf("change account: %d", code)
	}
	// The stored admin reflects the change.
	a, err := st.GetAdmin("boss")
	if err != nil {
		t.Fatalf("renamed admin not found: %v", err)
	}
	if !auth.VerifyPassword("brandnew1", a.PasswordHash) {
		t.Fatal("new password does not verify")
	}
	if _, err := st.GetAdmin("admin"); err == nil {
		t.Fatal("old username should no longer exist")
	}

	// A fresh login works only with the new credentials.
	jar2, _ := cookiejar.New(nil)
	c2 := &http.Client{Jar: jar2}
	if code := postJSON(t, c2, ts.URL+"/api/login", `{"username":"admin","password":"adminpass"}`, nil); code != 401 {
		t.Fatalf("old creds should fail, got %d", code)
	}
	if code := postJSON(t, c2, ts.URL+"/api/login", `{"username":"boss","password":"brandnew1"}`, nil); code != 200 {
		t.Fatalf("new creds should work, got %d", code)
	}
}

func TestInboundsAPI(t *testing.T) {
	ts, _ := setup(t)
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	postJSON(t, c, ts.URL+"/api/login", `{"username":"admin","password":"adminpass"}`, nil)

	// Invalid protocol rejected.
	if code := postJSON(t, c, ts.URL+"/api/inbounds", `{"tag":"x","protocol":"bogus","port":443}`, nil); code != 400 {
		t.Fatalf("bad protocol should be 400, got %d", code)
	}
	// Create valid.
	var in store.Inbound
	if code := postJSON(t, c, ts.URL+"/api/inbounds", `{"tag":"vless-443","protocol":"vless","port":443,"network":"tcp","security":"reality"}`, &in); code != 201 {
		t.Fatalf("create inbound: %d", code)
	}
	if in.ID == 0 || in.Security != "reality" {
		t.Fatalf("unexpected inbound: %+v", in)
	}
	// List.
	var list []store.Inbound
	getJSON(t, c, ts.URL+"/api/inbounds", &list)
	if len(list) != 1 {
		t.Fatalf("want 1 inbound, got %d", len(list))
	}
}

func TestBotAPIFlow(t *testing.T) {
	ts, st := setup(t)
	// Create an API token directly in the store.
	plain := auth.NewAPIToken()
	st.CreateAPIToken("bot", auth.HashToken(plain), "users:write")

	// Add an enabled location node so the subscription has content.
	st.CreateNode(&store.Node{Name: "nl-1", Role: store.RoleLocation, Location: "NL", Address: "nl.example.com:443", ServingMode: store.ServingBoth, Enabled: true})

	c := &http.Client{}

	// Missing token -> 401.
	req, _ := http.NewRequest("POST", ts.URL+"/botapi/users", strings.NewReader(`{"quota_gb":50,"days":30}`))
	resp, _ := c.Do(req)
	if resp.StatusCode != 401 {
		t.Fatalf("want 401 without token, got %d", resp.StatusCode)
	}

	// With token -> create user.
	var created map[string]any
	req, _ = http.NewRequest("POST", ts.URL+"/botapi/users", strings.NewReader(`{"username":"buyer1","quota_gb":50,"days":30}`))
	req.Header.Set("Authorization", "Bearer "+plain)
	resp, _ = c.Do(req)
	if resp.StatusCode != 201 {
		t.Fatalf("bot create want 201, got %d", resp.StatusCode)
	}
	json.NewDecoder(resp.Body).Decode(&created)
	uuid, _ := created["uuid"].(string)
	if uuid == "" {
		t.Fatal("no uuid returned")
	}
	if sub, _ := created["sub_link"].(string); !strings.Contains(sub, "/sub/") {
		t.Fatalf("missing sub link: %v", created["sub_link"])
	}

	// Renew.
	req, _ = http.NewRequest("POST", ts.URL+"/botapi/users/"+uuid+"/renew", strings.NewReader(`{"add_days":30,"add_gb":50}`))
	req.Header.Set("Authorization", "Bearer "+plain)
	resp, _ = c.Do(req)
	if resp.StatusCode != 200 {
		t.Fatalf("renew want 200, got %d", resp.StatusCode)
	}
	var renewed map[string]any
	json.NewDecoder(resp.Body).Decode(&renewed)
	if renewed["quota_bytes"].(float64) != float64(100*gib) {
		t.Fatalf("quota after renew = %v", renewed["quota_bytes"])
	}
}

// --- helpers ---

func postJSON(t *testing.T, c *http.Client, url, body string, out any) int {
	t.Helper()
	resp, err := c.Post(url, "application/json", bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil && resp.StatusCode/100 == 2 {
		json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

func getJSON(t *testing.T, c *http.Client, url string, out any) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	json.NewDecoder(resp.Body).Decode(out)
}
