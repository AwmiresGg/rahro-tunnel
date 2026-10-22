package api

import (
	"net/http"
	"strings"

	"github.com/awmiresgg/rahro/panel/tgbot"
)

// handleGetTelegram returns the current Telegram bot configuration. The token
// is masked (only whether it is set, plus its last 4 chars) so it is not
// re-exposed in full to the browser.
func (s *Server) handleGetTelegram(w http.ResponseWriter, r *http.Request) {
	tok, _, _ := s.Store.GetSetting(tgbot.SettingToken)
	admins, _, _ := s.Store.GetSetting(tgbot.SettingAdmins)
	tok = strings.TrimSpace(tok)
	hint := ""
	if len(tok) > 4 {
		hint = "…" + tok[len(tok)-4:]
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"configured": tok != "",
		"token_hint": hint,
		"admin_ids":  strings.TrimSpace(admins),
	})
}

// handleSetTelegram updates the bot token and/or admin IDs. An empty token
// field leaves the stored token unchanged; "-" clears it.
func (s *Server) handleSetTelegram(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token    *string `json:"token"`
		AdminIDs *string `json:"admin_ids"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, "bad request")
		return
	}
	if req.Token != nil {
		t := strings.TrimSpace(*req.Token)
		if t == "-" {
			t = ""
		}
		if t != "" || *req.Token == "-" {
			if err := s.Store.SetSetting(tgbot.SettingToken, t); err != nil {
				httpError(w, http.StatusInternalServerError, err.Error())
				return
			}
		}
	}
	if req.AdminIDs != nil {
		if err := s.Store.SetSetting(tgbot.SettingAdmins, strings.TrimSpace(*req.AdminIDs)); err != nil {
			httpError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
