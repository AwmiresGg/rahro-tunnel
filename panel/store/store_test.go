package store

import (
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestAdminCRUD(t *testing.T) {
	s := newTestStore(t)
	if n, _ := s.CountAdmins(); n != 0 {
		t.Fatalf("expected 0 admins, got %d", n)
	}
	if _, err := s.CreateAdmin("root", "hash1"); err != nil {
		t.Fatal(err)
	}
	a, err := s.GetAdmin("root")
	if err != nil || a.PasswordHash != "hash1" {
		t.Fatalf("get admin: %v %+v", err, a)
	}
	if err := s.UpdateAdminPassword("root", "hash2"); err != nil {
		t.Fatal(err)
	}
	a, _ = s.GetAdmin("root")
	if a.PasswordHash != "hash2" {
		t.Fatal("password not updated")
	}
	if _, err := s.GetAdmin("missing"); err != ErrNotFound {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestUserCRUDAndActive(t *testing.T) {
	s := newTestStore(t)
	u, err := s.CreateUser(&User{Username: "kian", UUID: "aaaa", SubToken: "tok1", QuotaBytes: 100, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if !u.Active() {
		t.Fatal("new user should be active")
	}

	got, err := s.GetUserBySubToken("tok1")
	if err != nil || got.ID != u.ID {
		t.Fatalf("get by sub token: %v", err)
	}

	// Usage accounting -> over quota -> inactive.
	if err := s.AddUsage(u.ID, 150); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetUser(u.ID)
	if got.Active() {
		t.Fatal("over-quota user should be inactive")
	}

	// Expiry.
	got.UsedBytes = 0
	got.QuotaBytes = 0
	got.ExpiresAt = time.Now().Add(-time.Hour).Unix()
	if err := s.UpdateUser(got); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetUser(u.ID)
	if got.Active() {
		t.Fatal("expired user should be inactive")
	}

	// Disabled.
	got.ExpiresAt = 0
	got.Enabled = false
	s.UpdateUser(got)
	got, _ = s.GetUser(u.ID)
	if got.Active() {
		t.Fatal("disabled user should be inactive")
	}

	if err := s.DeleteUser(u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetUser(u.ID); err != ErrNotFound {
		t.Fatalf("want ErrNotFound after delete, got %v", err)
	}
}

func TestUniqueConstraints(t *testing.T) {
	s := newTestStore(t)
	s.CreateUser(&User{Username: "a", UUID: "u1", SubToken: "s1", Enabled: true})
	if _, err := s.CreateUser(&User{Username: "a", UUID: "u2", SubToken: "s2"}); err == nil {
		t.Fatal("duplicate username should fail")
	}
	if _, err := s.CreateUser(&User{Username: "b", UUID: "u1", SubToken: "s3"}); err == nil {
		t.Fatal("duplicate uuid should fail")
	}
}

func TestNodeEnrollment(t *testing.T) {
	s := newTestStore(t)
	n, err := s.CreateNode(&Node{Name: "nl-1", Role: RoleLocation, Location: "NL", EnrollToken: "ENROLL123", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	// Wrong token.
	if _, err := s.EnrollNode("WRONG", "secret"); err != ErrNotFound {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	// Correct token -> stores secret, clears token.
	en, err := s.EnrollNode("ENROLL123", "node-secret")
	if err != nil || en.ID != n.ID {
		t.Fatalf("enroll: %v", err)
	}
	// Token no longer usable.
	if _, err := s.EnrollNode("ENROLL123", "x"); err != ErrNotFound {
		t.Fatal("enroll token should be single-use")
	}
	// Authenticate with secret.
	if _, err := s.AuthenticateNode(n.ID, "node-secret"); err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if _, err := s.AuthenticateNode(n.ID, "bad"); err != ErrNotFound {
		t.Fatal("wrong secret should fail")
	}
}

func TestInboundCRUD(t *testing.T) {
	s := newTestStore(t)
	in, err := s.CreateInbound(&Inbound{Tag: "vless-443", Protocol: ProtoVLESS, Port: 443, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if in.Network != "tcp" || in.Security != "tls" || in.Settings != "{}" {
		t.Fatalf("defaults not applied: %+v", in)
	}
	in.Port = 8443
	in.Remark = "main"
	if err := s.UpdateInbound(in); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetInbound(in.ID)
	if got.Port != 8443 || got.Remark != "main" {
		t.Fatalf("update not persisted: %+v", got)
	}
	// Duplicate tag rejected.
	if _, err := s.CreateInbound(&Inbound{Tag: "vless-443", Protocol: ProtoVLESS, Port: 1}); err == nil {
		t.Fatal("duplicate tag should fail")
	}
	list, _ := s.ListInbounds()
	if len(list) != 1 {
		t.Fatalf("want 1 inbound, got %d", len(list))
	}
	if err := s.DeleteInbound(in.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetInbound(in.ID); err != ErrNotFound {
		t.Fatal("inbound should be gone")
	}
}

func TestAPITokensAndSettings(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.CreateAPIToken("bot", "hash-abc", "users:write"); err != nil {
		t.Fatal(err)
	}
	tok, err := s.AuthenticateAPIToken("hash-abc")
	if err != nil || tok.Name != "bot" {
		t.Fatalf("auth token: %v", err)
	}
	if _, err := s.AuthenticateAPIToken("nope"); err != ErrNotFound {
		t.Fatal("unknown token should fail")
	}

	if _, ok, _ := s.GetSetting("k"); ok {
		t.Fatal("unset key should return ok=false")
	}
	s.SetSetting("k", "v1")
	s.SetSetting("k", "v2")
	v, ok, _ := s.GetSetting("k")
	if !ok || v != "v2" {
		t.Fatalf("setting upsert failed: %q %v", v, ok)
	}
}
