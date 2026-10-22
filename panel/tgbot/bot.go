// Package tgbot is Rahro's built-in Telegram bot: a long-polling client that
// lets an admin manage users from Telegram and pushes quota/expiry alerts. It
// depends only on the store (plus auth), with an onChange callback to reload
// Xray, so it never imports the api/panel layer.
package tgbot

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/awmiresgg/rahro/panel/store"
)

const (
	// Settings keys the panel/menu write and the bot reads live.
	SettingToken   = "tg_bot_token"
	SettingAdmins  = "tg_admin_ids"
	pollTimeoutSec = 30
)

// apiBase is the Telegram Bot API prefix; a var so tests can point it at a mock.
var apiBase = "https://api.telegram.org/bot"

// Bot polls Telegram and acts on admin commands.
type Bot struct {
	store      *store.Store
	publicBase string
	onChange   func() // reload Xray after a mutation
	log        *slog.Logger
	http       *http.Client

	mu      sync.Mutex
	alerted map[string]bool // "<uuid>:<kind>" already notified
	offset  int64           // getUpdates offset
}

// New creates a bot bound to a store. publicBase builds subscription links;
// onChange (may be nil) is called after any change that affects Xray.
func New(st *store.Store, publicBase string, onChange func(), log *slog.Logger) *Bot {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if onChange == nil {
		onChange = func() {}
	}
	return &Bot{
		store: st, publicBase: strings.TrimRight(publicBase, "/"),
		onChange: onChange, log: log,
		http:    &http.Client{Timeout: (pollTimeoutSec + 15) * time.Second},
		alerted: map[string]bool{},
	}
}

// token / admins are read live from settings so the admin can configure the
// bot from the panel without a restart.
func (b *Bot) token() string {
	v, _, _ := b.store.GetSetting(SettingToken)
	return strings.TrimSpace(v)
}

func (b *Bot) admins() map[int64]bool {
	v, _, _ := b.store.GetSetting(SettingAdmins)
	out := map[int64]bool{}
	for _, p := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		if id, err := strconv.ParseInt(strings.TrimSpace(p), 10, 64); err == nil {
			out[id] = true
		}
	}
	return out
}

// Run drives the bot until ctx is cancelled: it long-polls for commands and,
// on a slower cadence, scans for quota/expiry alerts. It tolerates the token
// being absent or changed at runtime.
func (b *Bot) Run(ctx context.Context) {
	alertTick := time.NewTicker(60 * time.Second)
	defer alertTick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-alertTick.C:
			if b.token() != "" {
				b.checkAlerts()
			}
		default:
			tok := b.token()
			if tok == "" {
				// Not configured yet; wait and re-check without burning CPU.
				select {
				case <-ctx.Done():
					return
				case <-time.After(15 * time.Second):
				}
				continue
			}
			b.pollOnce(ctx, tok)
		}
	}
}

// pollOnce performs a single long-poll getUpdates and dispatches messages.
func (b *Bot) pollOnce(ctx context.Context, tok string) {
	b.mu.Lock()
	off := b.offset
	b.mu.Unlock()

	u := fmt.Sprintf("%s%s/getUpdates?timeout=%d&offset=%d", apiBase, tok, pollTimeoutSec, off)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	resp, err := b.http.Do(req)
	if err != nil {
		if ctx.Err() == nil {
			time.Sleep(3 * time.Second) // transient network error; back off
		}
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var res struct {
		OK     bool     `json:"ok"`
		Result []update `json:"result"`
	}
	if err := json.Unmarshal(body, &res); err != nil || !res.OK {
		time.Sleep(3 * time.Second)
		return
	}
	for _, up := range res.Result {
		b.mu.Lock()
		if up.UpdateID >= b.offset {
			b.offset = up.UpdateID + 1
		}
		b.mu.Unlock()
		if up.Message != nil && up.Message.Text != "" {
			b.handleCommand(up.Message)
		}
	}
}

// --- Telegram wire types (minimal) ---

type update struct {
	UpdateID int64    `json:"update_id"`
	Message  *message `json:"message"`
}

type message struct {
	MessageID int64  `json:"message_id"`
	Text      string `json:"text"`
	Chat      chat   `json:"chat"`
	From      *user  `json:"from"`
}

type chat struct {
	ID int64 `json:"id"`
}

type user struct {
	ID        int64  `json:"id"`
	FirstName string `json:"first_name"`
	Username  string `json:"username"`
}

// --- outbound helpers ---

// send posts an HTML message to a chat.
func (b *Bot) send(chatID int64, text string) {
	tok := b.token()
	if tok == "" {
		return
	}
	form := url.Values{
		"chat_id":                  {strconv.FormatInt(chatID, 10)},
		"text":                     {text},
		"parse_mode":               {"HTML"},
		"disable_web_page_preview": {"true"},
	}
	resp, err := b.http.PostForm(apiBase+tok+"/sendMessage", form)
	if err != nil {
		b.log.Debug("tg send failed", "err", err)
		return
	}
	resp.Body.Close()
}

// sendDocument uploads a file (used for backups).
func (b *Bot) sendDocument(chatID int64, name string, data []byte) {
	tok := b.token()
	if tok == "" {
		return
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("chat_id", strconv.FormatInt(chatID, 10))
	fw, err := mw.CreateFormFile("document", name)
	if err == nil {
		fw.Write(data)
	}
	mw.Close()
	req, _ := http.NewRequest(http.MethodPost, apiBase+tok+"/sendDocument", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := b.http.Do(req)
	if err != nil {
		b.log.Debug("tg sendDocument failed", "err", err)
		return
	}
	resp.Body.Close()
}

// broadcast sends a message to every configured admin.
func (b *Bot) broadcast(text string) {
	for id := range b.admins() {
		b.send(id, text)
	}
}
