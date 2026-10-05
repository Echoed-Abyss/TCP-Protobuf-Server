package admin

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/appapi"
)

// maxActionBody caps the JSON body accepted by the action endpoints.
const maxActionBody = 1 << 20 // 1 MiB

// handleActions serves the action collection:
//
//	GET  /admin/actions        -> [ActionDef, ...]
//	PUT  /admin/actions        -> upsert one ActionDef (body = the definition)
func (s *Server) handleActions(w http.ResponseWriter, r *http.Request) {
	if s.actions == nil {
		http.Error(w, "action store disabled", http.StatusNotImplemented)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.actions.List())

	case http.MethodPut:
		var def appapi.ActionDef
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxActionBody)).Decode(&def); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid JSON body"})
			return
		}
		if err := s.actions.Put(def); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "name": def.Name})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleActionOp serves a single action:
//
//	DELETE /admin/actions/{name}
func (s *Server) handleActionOp(w http.ResponseWriter, r *http.Request) {
	if s.actions == nil {
		http.Error(w, "action store disabled", http.StatusNotImplemented)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/admin/actions/")
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "missing name"})
		return
	}
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.actions.Delete(name); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": name})
}

// handleActionTest renders a stored definition without sending it over the
// wire, so definitions can be verified from the UI before a client uses them:
//
//	POST /admin/actions/test  {"name":"get_xuan_accpass","payload":{"qq":10001}}
//	-> the exact response envelope a client would receive
func (s *Server) handleActionTest(w http.ResponseWriter, r *http.Request) {
	if s.actions == nil {
		http.Error(w, "action store disabled", http.StatusNotImplemented)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Name    string          `json:"name"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxActionBody)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid JSON body"})
		return
	}
	def, ok := s.actions.Get(body.Name)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "action not defined"})
		return
	}
	writeJSON(w, http.StatusOK, appapi.ExecuteAction(def, "admin-test", body.Payload))
}
