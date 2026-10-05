package appapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestExecuteActionLookupAndTemplate(t *testing.T) {
	def := ActionDef{
		Name:     "get_xuan_accpass",
		Enabled:  true,
		Required: []string{"qq"},
		Lookup: &LookupDef{
			Key: "qq",
			Rows: []map[string]any{
				{"qq": float64(10001), "account": "xuan_main", "password": "P@ss", "roles": []any{"admin", "vip"}},
			},
		},
		Response: json.RawMessage(`{"account":"${row.account}","password":"${row.password}","you":"${payload.qq}","roles":"${row.roles}","note":"acc=${row.account}"}`),
	}

	resp := ExecuteAction(def, "r1", json.RawMessage(`{"qq":10001}`))
	if !resp.Ok {
		t.Fatalf("expected ok, got code=%s", resp.Code)
	}

	var got map[string]any
	if err := json.Unmarshal(resp.Data, &got); err != nil {
		t.Fatalf("unmarshal data: %v", err)
	}
	if got["account"] != "xuan_main" || got["password"] != "P@ss" {
		t.Fatalf("row fields not substituted: %v", got)
	}
	// A whole-string placeholder must preserve the JSON type.
	if v, ok := got["you"].(float64); !ok || v != 10001 {
		t.Fatalf("number type not preserved: %#v", got["you"])
	}
	if _, ok := got["roles"].([]any); !ok {
		t.Fatalf("array type not preserved: %#v", got["roles"])
	}
	// Embedded placeholder is stringified in place.
	if got["note"] != "acc=xuan_main" {
		t.Fatalf("inline substitution failed: %#v", got["note"])
	}
}

func TestExecuteActionErrors(t *testing.T) {
	base := ActionDef{
		Name:     "lookup",
		Enabled:  true,
		Required: []string{"qq"},
		Lookup:   &LookupDef{Key: "qq", Rows: []map[string]any{{"qq": float64(1), "v": "one"}}},
		Response: json.RawMessage(`{"v":"${row.v}"}`),
	}

	if r := ExecuteAction(base, "r", json.RawMessage(`{}`)); r.Code != CodeBadRequest {
		t.Fatalf("missing required field: want bad_request, got %s", r.Code)
	}
	if r := ExecuteAction(base, "r", json.RawMessage(`{"qq":999}`)); r.Code != CodeNotFound {
		t.Fatalf("no matching row: want not_found, got %s", r.Code)
	}
	// String payload key still matches a numeric row key.
	if r := ExecuteAction(base, "r", json.RawMessage(`{"qq":"1"}`)); !r.Ok {
		t.Fatalf("scalar match across types should succeed, got %s", r.Code)
	}
	// A definition with neither required nor lookup renders unconditionally.
	plain := ActionDef{Name: "plain", Enabled: true, Response: json.RawMessage(`{"ok":true}`)}
	if r := ExecuteAction(plain, "r", nil); !r.Ok {
		t.Fatalf("plain template should render, got %s", r.Code)
	}
}

func TestExecuteActionPureTemplate(t *testing.T) {
	def := ActionDef{
		Name:     "ping",
		Enabled:  true,
		Response: json.RawMessage(`{"pong":true,"echo":"${payload.msg}"}`),
	}
	resp := ExecuteAction(def, "r", json.RawMessage(`{"msg":"hi"}`))
	if !resp.Ok {
		t.Fatalf("want ok, got %s", resp.Code)
	}
	var got map[string]any
	_ = json.Unmarshal(resp.Data, &got)
	if got["pong"] != true || got["echo"] != "hi" {
		t.Fatalf("unexpected render: %v", got)
	}
}

func TestActionStorePersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "actions.db")
	st, err := NewActionStore(path)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	def := ActionDef{Name: "get_xuan_accpass", Enabled: true, Response: json.RawMessage(`{"ok":true}`)}
	if err := st.Put(def); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := st.Put(ActionDef{Name: "bad name!", Enabled: true, Response: json.RawMessage(`{}`)}); err == nil {
		t.Fatal("expected validation error for invalid name")
	}

	reloaded, err := NewActionStore(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	t.Cleanup(func() { _ = reloaded.Close() })
	if got, ok := reloaded.Get("get_xuan_accpass"); !ok || !got.Enabled {
		t.Fatalf("definition did not persist")
	}
	if fi, err := os.Stat(path); err != nil || fi.Size() == 0 {
		t.Fatalf("sqlite database file missing or empty: %v", err)
	}
	if err := reloaded.Delete("get_xuan_accpass"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok := reloaded.Get("get_xuan_accpass"); ok {
		t.Fatal("delete did not take effect")
	}
}

func TestRegistryFallbackDispatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "actions.db")
	st, err := NewActionStore(path)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Put(ActionDef{
		Name:     "get_xuan_accpass",
		Enabled:  true,
		Required: []string{"qq"},
		Lookup:   &LookupDef{Key: "qq", Rows: []map[string]any{{"qq": float64(10001), "acc": "a"}}},
		Response: json.RawMessage(`{"acc":"${row.acc}"}`),
	}); err != nil {
		t.Fatalf("put: %v", err)
	}

	srv := NewServer(NewRegistry(), 0)
	srv.RegisterDefaults()
	srv.EnableDynamicActions(st)

	// Built-in handlers still win.
	if h, ok := srv.registry.Lookup("echo"); !ok || h == nil {
		t.Fatal("built-in echo should resolve")
	}
	// Unknown name falls through to the dynamic router.
	h, ok := srv.registry.Lookup("get_xuan_accpass")
	if !ok {
		t.Fatal("dynamic action should resolve via fallback")
	}
	resp, err := h(context.Background(), &Request{Action: "get_xuan_accpass", Payload: json.RawMessage(`{"qq":10001}`)})
	if err != nil || resp == nil || !resp.Ok {
		t.Fatalf("dynamic dispatch failed: %v %#v", err, resp)
	}

	// An action that is not in the store must not resolve to ok.
	h2, _ := srv.registry.Lookup("nope")
	resp2, _ := h2(context.Background(), &Request{Action: "nope"})
	if resp2 == nil || resp2.Code != CodeNotFound {
		t.Fatalf("unknown action should be not_found, got %#v", resp2)
	}
}
