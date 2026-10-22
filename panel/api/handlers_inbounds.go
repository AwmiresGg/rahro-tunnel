package api

import (
	"net/http"

	"github.com/awmiresgg/rahro/panel/store"
)

var validProtocols = map[string]bool{
	store.ProtoVLESS: true, store.ProtoVMess: true,
	store.ProtoTrojan: true, store.ProtoShadowsocks: true,
}

func (s *Server) handleListInbounds(w http.ResponseWriter, r *http.Request) {
	ins, err := s.Store.ListInbounds()
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if ins == nil {
		ins = []*store.Inbound{}
	}
	writeJSON(w, http.StatusOK, ins)
}

func (s *Server) handleCreateInbound(w http.ResponseWriter, r *http.Request) {
	var in store.Inbound
	if err := readJSON(r, &in); err != nil {
		httpError(w, http.StatusBadRequest, "bad request")
		return
	}
	if err := validateInbound(&in); err != "" {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	in.Enabled = true
	created, err := s.Store.CreateInbound(&in)
	if err != nil {
		httpError(w, http.StatusConflict, err.Error())
		return
	}
	s.ApplyXray()
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleGetInbound(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, "bad id")
		return
	}
	in, err := s.Store.GetInbound(id)
	if err != nil {
		httpError(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, in)
}

func (s *Server) handleUpdateInbound(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, "bad id")
		return
	}
	existing, err := s.Store.GetInbound(id)
	if err != nil {
		httpError(w, http.StatusNotFound, "not found")
		return
	}
	var in store.Inbound
	if err := readJSON(r, &in); err != nil {
		httpError(w, http.StatusBadRequest, "bad request")
		return
	}
	in.ID = existing.ID
	in.CreatedAt = existing.CreatedAt
	if msg := validateInbound(&in); msg != "" {
		httpError(w, http.StatusBadRequest, msg)
		return
	}
	if err := s.Store.UpdateInbound(&in); err != nil {
		httpError(w, http.StatusConflict, err.Error())
		return
	}
	s.ApplyXray()
	writeJSON(w, http.StatusOK, &in)
}

func (s *Server) handleDeleteInbound(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, "bad id")
		return
	}
	if err := s.Store.DeleteInbound(id); err != nil {
		httpError(w, http.StatusNotFound, "not found")
		return
	}
	s.ApplyXray()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// validateInbound returns an error message, or "" when valid.
func validateInbound(in *store.Inbound) string {
	if in.Tag == "" {
		return "tag is required"
	}
	if !validProtocols[in.Protocol] {
		return "protocol must be vless|vmess|trojan|shadowsocks"
	}
	if in.Port < 1 || in.Port > 65535 {
		return "port must be 1-65535"
	}
	switch in.Network {
	case "", "tcp", "ws", "grpc", "http", "quic":
	default:
		return "network must be tcp|ws|grpc|http|quic"
	}
	switch in.Security {
	case "", "none", "tls", "reality":
	default:
		return "security must be none|tls|reality"
	}
	return ""
}
