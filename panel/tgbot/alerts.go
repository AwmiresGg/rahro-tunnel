package tgbot

import (
	"fmt"
	"strings"
	"time"

	"github.com/awmiresgg/rahro/panel/store"
)

// expirySoon is how far ahead an upcoming expiry triggers a warning.
const expirySoon = 72 * time.Hour

type alertKind struct {
	kind string
	text string
}

// userAlerts returns the alert conditions a user currently meets. Pure (no IO)
// so it can be unit-tested. Only enabled users are considered.
func userAlerts(u *store.User, now time.Time) []alertKind {
	if !u.Enabled {
		return nil
	}
	var out []alertKind
	if u.QuotaBytes > 0 {
		switch {
		case u.UsedBytes >= u.QuotaBytes:
			out = append(out, alertKind{"quota_full",
				fmt.Sprintf("🔴 <b>%s</b> reached its data limit (%s/%s).",
					escapeHTML(u.Username), fmtBytes(u.UsedBytes), fmtQuota(u.QuotaBytes))})
		case u.UsedBytes*100 >= u.QuotaBytes*80:
			out = append(out, alertKind{"quota_80",
				fmt.Sprintf("🟠 <b>%s</b> used 80%% of data (%s/%s).",
					escapeHTML(u.Username), fmtBytes(u.UsedBytes), fmtQuota(u.QuotaBytes))})
		}
	}
	if u.ExpiresAt > 0 {
		exp := time.Unix(u.ExpiresAt, 0)
		switch {
		case !now.Before(exp):
			out = append(out, alertKind{"expired",
				fmt.Sprintf("🔴 <b>%s</b> has expired (%s).", escapeHTML(u.Username), fmtExpiry(u.ExpiresAt))})
		case exp.Sub(now) <= expirySoon:
			out = append(out, alertKind{"exp_soon",
				fmt.Sprintf("🟠 <b>%s</b> expires %s.", escapeHTML(u.Username), fmtExpiry(u.ExpiresAt))})
		}
	}
	return out
}

// checkAlerts scans users and sends any newly-met alert to the admins, once per
// (user, kind). When a condition no longer holds the memo is cleared so it can
// fire again later (e.g. after a renew then a second depletion).
func (b *Bot) checkAlerts() {
	if len(b.admins()) == 0 {
		return
	}
	users, err := b.store.ListUsers()
	if err != nil {
		return
	}
	now := time.Now()
	for _, u := range users {
		active := map[string]bool{}
		for _, a := range userAlerts(u, now) {
			active[a.kind] = true
			key := u.UUID + ":" + a.kind
			b.mu.Lock()
			already := b.alerted[key]
			if !already {
				b.alerted[key] = true
			}
			b.mu.Unlock()
			if !already {
				b.broadcast(a.text)
			}
		}
		// Clear memos for conditions that no longer apply.
		b.mu.Lock()
		for _, k := range []string{"quota_full", "quota_80", "expired", "exp_soon"} {
			if !active[k] {
				delete(b.alerted, u.UUID+":"+k)
			}
		}
		b.mu.Unlock()
	}
}

// clearAlerts drops all alert memos for a user (after renew/reset/delete).
func (b *Bot) clearAlerts(uuid string) {
	b.mu.Lock()
	for _, k := range []string{"quota_full", "quota_80", "expired", "exp_soon"} {
		delete(b.alerted, uuid+":"+k)
	}
	b.mu.Unlock()
}

// --- formatting ---

func escapeHTML(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func fmtBytes(n int64) string {
	switch {
	case n >= gib:
		return fmt.Sprintf("%.2f GB", float64(n)/float64(gib))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%d KB", n/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func fmtQuota(n int64) string {
	if n <= 0 {
		return "∞"
	}
	return fmt.Sprintf("%d GB", n/gib)
}

func fmtExpiry(ts int64) string {
	if ts <= 0 {
		return "never"
	}
	return time.Unix(ts, 0).UTC().Format("2006-01-02")
}
