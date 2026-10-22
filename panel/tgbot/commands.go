package tgbot

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/awmiresgg/rahro/panel/auth"
	"github.com/awmiresgg/rahro/panel/store"
)

const gib = int64(1) << 30

const helpText = `<b>Rahro bot</b> — admin commands:
/status — users &amp; nodes overview
/list [n] — recent users
/add &lt;name&gt; &lt;GB&gt; &lt;days&gt; — create a user (0 = unlimited/never)
/find &lt;name|uuid&gt; — show a user + sub link
/renew &lt;name|uuid&gt; &lt;days&gt; [GB] — extend / top up
/reset &lt;name|uuid&gt; — reset used traffic
/del &lt;name|uuid&gt; — delete a user
/backup — download a database backup
/id — show this chat's ID`

// handleCommand dispatches one incoming message.
func (b *Bot) handleCommand(m *message) {
	fields := strings.Fields(m.Text)
	if len(fields) == 0 {
		return
	}
	cmd := strings.ToLower(fields[0])
	if i := strings.IndexByte(cmd, '@'); i >= 0 { // strip @botname
		cmd = cmd[:i]
	}
	args := fields[1:]
	chatID := m.Chat.ID

	if cmd == "/id" || cmd == "/start" {
		b.replyStart(chatID, cmd)
		return
	}
	if !b.admins()[chatID] {
		b.send(chatID, fmt.Sprintf("⛔ You are not an admin.\nYour chat ID is <code>%d</code> — add it to the panel (Settings → Telegram) to enable admin commands.", chatID))
		return
	}

	switch cmd {
	case "/help":
		b.send(chatID, helpText)
	case "/status":
		b.cmdStatus(chatID)
	case "/list":
		n := 10
		if len(args) > 0 {
			if v, err := strconv.Atoi(args[0]); err == nil && v > 0 && v <= 100 {
				n = v
			}
		}
		b.cmdList(chatID, n)
	case "/add":
		b.cmdAdd(chatID, args)
	case "/find":
		b.cmdFind(chatID, args)
	case "/renew":
		b.cmdRenew(chatID, args)
	case "/reset":
		b.cmdReset(chatID, args)
	case "/del":
		b.cmdDel(chatID, args)
	case "/backup":
		b.cmdBackup(chatID)
	default:
		b.send(chatID, "Unknown command. "+helpText)
	}
}

func (b *Bot) replyStart(chatID int64, cmd string) {
	if b.admins()[chatID] {
		b.send(chatID, helpText)
		return
	}
	b.send(chatID, fmt.Sprintf("👋 Rahro bot.\nYour chat ID is <code>%d</code>.\nAdd it in the panel (Settings → Telegram admin IDs) to use admin commands.", chatID))
}

func (b *Bot) cmdStatus(chatID int64) {
	users, _ := b.store.ListUsers()
	nodes, _ := b.store.ListNodes()
	active, online := 0, 0
	for _, u := range users {
		if u.Active() {
			active++
		}
	}
	for _, n := range nodes {
		if n.Enabled {
			online++
		}
	}
	b.send(chatID, fmt.Sprintf(
		"<b>Rahro status</b>\n👥 Users: %d (active %d)\n🌐 Nodes: %d (enabled %d)\n🕒 %s",
		len(users), active, len(nodes), online, time.Now().UTC().Format("2006-01-02 15:04 MST")))
}

func (b *Bot) cmdList(chatID int64, n int) {
	users, _ := b.store.ListUsers()
	if len(users) == 0 {
		b.send(chatID, "No users yet.")
		return
	}
	if len(users) > n {
		users = users[:n]
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("<b>Users (showing %d)</b>\n", len(users)))
	for _, u := range users {
		state := "✅"
		if !u.Active() {
			state = "⛔"
		}
		sb.WriteString(fmt.Sprintf("%s <b>%s</b> — %s/%s — exp %s\n",
			state, escapeHTML(u.Username), fmtBytes(u.UsedBytes), fmtQuota(u.QuotaBytes), fmtExpiry(u.ExpiresAt)))
	}
	b.send(chatID, sb.String())
}

func (b *Bot) cmdAdd(chatID int64, args []string) {
	if len(args) < 3 {
		b.send(chatID, "Usage: /add &lt;name&gt; &lt;GB&gt; &lt;days&gt;  (0 = unlimited/never)")
		return
	}
	name := args[0]
	gb, err1 := strconv.ParseInt(args[1], 10, 64)
	days, err2 := strconv.ParseInt(args[2], 10, 64)
	if err1 != nil || err2 != nil || gb < 0 || days < 0 {
		b.send(chatID, "GB and days must be non-negative numbers.")
		return
	}
	u := &store.User{
		Username: name, UUID: auth.NewUUIDHex(), SubToken: auth.NewToken(18),
		QuotaBytes: gb * gib, Enabled: true,
	}
	if days > 0 {
		u.ExpiresAt = time.Now().Add(time.Duration(days) * 24 * time.Hour).Unix()
	}
	created, err := b.store.CreateUser(u)
	if err != nil {
		b.send(chatID, "❌ Could not create user: "+escapeHTML(err.Error()))
		return
	}
	b.onChange()
	b.send(chatID, fmt.Sprintf("✅ Created <b>%s</b>\nQuota: %s · Expiry: %s\n\n<code>%s</code>",
		escapeHTML(created.Username), fmtQuota(created.QuotaBytes), fmtExpiry(created.ExpiresAt), b.subLink(created)))
}

func (b *Bot) cmdFind(chatID int64, args []string) {
	if len(args) < 1 {
		b.send(chatID, "Usage: /find &lt;name|uuid&gt;")
		return
	}
	u := b.lookup(args[0])
	if u == nil {
		b.send(chatID, "Not found.")
		return
	}
	state := "active ✅"
	if !u.Active() {
		state = "inactive ⛔"
	}
	b.send(chatID, fmt.Sprintf("<b>%s</b> (%s)\nUsage: %s / %s\nExpiry: %s\nUUID: <code>%s</code>\n\n<code>%s</code>",
		escapeHTML(u.Username), state, fmtBytes(u.UsedBytes), fmtQuota(u.QuotaBytes), fmtExpiry(u.ExpiresAt), u.UUID, b.subLink(u)))
}

func (b *Bot) cmdRenew(chatID int64, args []string) {
	if len(args) < 2 {
		b.send(chatID, "Usage: /renew &lt;name|uuid&gt; &lt;days&gt; [GB]")
		return
	}
	u := b.lookup(args[0])
	if u == nil {
		b.send(chatID, "Not found.")
		return
	}
	days, _ := strconv.ParseInt(args[1], 10, 64)
	var gb int64
	if len(args) >= 3 {
		gb, _ = strconv.ParseInt(args[2], 10, 64)
	}
	base := time.Now()
	if u.ExpiresAt > base.Unix() {
		base = time.Unix(u.ExpiresAt, 0)
	}
	if days > 0 {
		u.ExpiresAt = base.Add(time.Duration(days) * 24 * time.Hour).Unix()
	}
	if gb > 0 {
		u.QuotaBytes += gb * gib
	}
	u.Enabled = true
	if err := b.store.UpdateUser(u); err != nil {
		b.send(chatID, "❌ "+escapeHTML(err.Error()))
		return
	}
	b.clearAlerts(u.UUID)
	b.onChange()
	b.send(chatID, fmt.Sprintf("✅ Renewed <b>%s</b>\nQuota: %s · Expiry: %s",
		escapeHTML(u.Username), fmtQuota(u.QuotaBytes), fmtExpiry(u.ExpiresAt)))
}

func (b *Bot) cmdReset(chatID int64, args []string) {
	if len(args) < 1 {
		b.send(chatID, "Usage: /reset &lt;name|uuid&gt;")
		return
	}
	u := b.lookup(args[0])
	if u == nil {
		b.send(chatID, "Not found.")
		return
	}
	if err := b.store.ResetUsage(u.ID); err != nil {
		b.send(chatID, "❌ "+escapeHTML(err.Error()))
		return
	}
	b.clearAlerts(u.UUID)
	b.onChange()
	b.send(chatID, fmt.Sprintf("✅ Reset traffic for <b>%s</b>.", escapeHTML(u.Username)))
}

func (b *Bot) cmdDel(chatID int64, args []string) {
	if len(args) < 1 {
		b.send(chatID, "Usage: /del &lt;name|uuid&gt;")
		return
	}
	u := b.lookup(args[0])
	if u == nil {
		b.send(chatID, "Not found.")
		return
	}
	if err := b.store.DeleteUser(u.ID); err != nil {
		b.send(chatID, "❌ "+escapeHTML(err.Error()))
		return
	}
	b.clearAlerts(u.UUID)
	b.onChange()
	b.send(chatID, fmt.Sprintf("🗑 Deleted <b>%s</b>.", escapeHTML(u.Username)))
}

func (b *Bot) cmdBackup(chatID int64) {
	data, err := b.store.Backup()
	if err != nil {
		b.send(chatID, "❌ backup failed: "+escapeHTML(err.Error()))
		return
	}
	b.sendDocument(chatID, "rahro-"+time.Now().UTC().Format("20060102-150405")+".db", data)
}

// lookup finds a user by UUID first, then username.
func (b *Bot) lookup(q string) *store.User {
	if u, err := b.store.GetUserByUUID(q); err == nil {
		return u
	}
	if u, err := b.store.GetUserByUsername(q); err == nil {
		return u
	}
	return nil
}

func (b *Bot) subLink(u *store.User) string {
	return b.publicBase + "/sub/" + u.SubToken
}
