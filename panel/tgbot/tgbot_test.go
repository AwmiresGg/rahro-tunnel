package tgbot

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awmiresgg/rahro/panel/store"
)

func TestUserAlerts(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	day := int64(86400)
	cases := []struct {
		name string
		u    *store.User
		want []string // kinds expected
	}{
		{"healthy", &store.User{Enabled: true, QuotaBytes: 100, UsedBytes: 10, ExpiresAt: now.Unix() + 30*day}, nil},
		{"quota80", &store.User{Enabled: true, QuotaBytes: 100, UsedBytes: 85}, []string{"quota_80"}},
		{"quotafull", &store.User{Enabled: true, QuotaBytes: 100, UsedBytes: 100}, []string{"quota_full"}},
		{"expsoon", &store.User{Enabled: true, ExpiresAt: now.Unix() + 2*day}, []string{"exp_soon"}},
		{"expired", &store.User{Enabled: true, ExpiresAt: now.Unix() - 1}, []string{"expired"}},
		{"disabled", &store.User{Enabled: false, QuotaBytes: 100, UsedBytes: 100}, nil},
		{"both", &store.User{Enabled: true, QuotaBytes: 100, UsedBytes: 100, ExpiresAt: now.Unix() - 1}, []string{"quota_full", "expired"}},
	}
	for _, c := range cases {
		got := userAlerts(c.u, now)
		var kinds []string
		for _, a := range got {
			kinds = append(kinds, a.kind)
		}
		if strings.Join(kinds, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: got %v want %v", c.name, kinds, c.want)
		}
	}
}

func TestAdminsParsing(t *testing.T) {
	st := memStore(t)
	b := New(st, "http://x", nil, nil)
	st.SetSetting(SettingAdmins, " 111, 222 333\n444 ")
	a := b.admins()
	for _, id := range []int64{111, 222, 333, 444} {
		if !a[id] {
			t.Errorf("admin %d missing from %v", id, a)
		}
	}
	if a[999] {
		t.Error("unexpected admin 999")
	}
}

// TestCommandDispatch runs a non-admin and an admin command against a mock
// Telegram API and checks the replies the bot sends.
func TestCommandDispatch(t *testing.T) {
	var mu sync.Mutex
	var sent []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/sendMessage") {
			r.ParseForm()
			mu.Lock()
			sent = append(sent, r.FormValue("text"))
			mu.Unlock()
		}
		io.WriteString(w, `{"ok":true,"result":{}}`)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL + "/bot"
	defer func() { apiBase = old }()

	st := memStore(t)
	st.SetSetting(SettingToken, "TESTTOKEN")
	st.SetSetting(SettingAdmins, "500")
	b := New(st, "http://panel.example:2053", nil, nil)

	// Non-admin gets their chat id echoed, not admin help.
	b.handleCommand(&message{Text: "/status", Chat: chat{ID: 777}})
	// Admin create + status.
	b.handleCommand(&message{Text: "/add buyer 10 30", Chat: chat{ID: 500}})
	b.handleCommand(&message{Text: "/status", Chat: chat{ID: 500}})

	mu.Lock()
	defer mu.Unlock()
	joined := strings.Join(sent, "\n---\n")
	if !strings.Contains(joined, "not an admin") || !strings.Contains(joined, "777") {
		t.Errorf("non-admin reply missing chat id/notice:\n%s", joined)
	}
	if !strings.Contains(joined, "Created") || !strings.Contains(joined, "/sub/") {
		t.Errorf("add reply missing sub link:\n%s", joined)
	}
	if !strings.Contains(joined, "Rahro status") {
		t.Errorf("status reply missing:\n%s", joined)
	}
	// The user really was created.
	if _, err := st.GetUserByUsername("buyer"); err != nil {
		t.Errorf("buyer not created: %v", err)
	}
}

func TestSendFormEncodes(t *testing.T) {
	var got url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		got = r.Form
		io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL + "/bot"
	defer func() { apiBase = old }()
	st := memStore(t)
	st.SetSetting(SettingToken, "T")
	b := New(st, "http://x", nil, nil)
	b.send(42, "<b>hi</b>")
	if got.Get("chat_id") != "42" || got.Get("text") != "<b>hi</b>" || got.Get("parse_mode") != "HTML" {
		t.Errorf("bad send form: %v", got)
	}
}

func memStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}
