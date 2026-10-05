// Runtime-defined actions.
//
// Besides the compile-time handlers registered through Registry.Register,
// the server supports *dynamic actions*: definitions created and edited at
// runtime from the admin UI/API and persisted to a store. A definition is
// plain JSON:
//
//	{
//	  "name":     "get_xuan_accpass",
//	  "enabled":  true,
//	  "desc":     "查询玄账号密码",
//	  "required": ["qq"],
//	  "lookup": {
//	    "key": "qq",
//	    "rows": [ {"qq": 10001, "account": "xuan_main", "password": "P@ss"} ]
//	  },
//	  "response": {
//	    "account":  "${row.account}",
//	    "password": "${row.password}",
//	    "echo_qq":  "${payload.qq}"
//	  }
//	}
//
// The `response` template is free-form JSON. Inside it, any string of the
// form ${payload.a.b} or ${row.x} is substituted:
//
//   - a string that is exactly one placeholder is replaced by the raw value,
//     so numbers, booleans, arrays and objects keep their JSON type;
//   - placeholders embedded in a longer string are stringified in place;
//   - an unresolved placeholder is left verbatim, which makes mistakes
//     obvious when using the admin "试运行" button.
//
// Definitions are stored by ActionStore, a single-file SQLite table, so the
// whole set can be inspected, backed up, or edited with standard tooling.
package appapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

// LookupDef selects one row from an inline table using a request field.
// When Lookup is nil the response template is rendered from the request
// payload alone (pure static/templated action).
type LookupDef struct {
	// Key is the field name used both to read the payload and to match rows.
	Key string `json:"key"`
	// Rows is the inline table. Each row is an arbitrary JSON object.
	Rows []map[string]any `json:"rows"`
}

// ActionDef is a runtime-defined action.
type ActionDef struct {
	Name     string          `json:"name"`
	Enabled  bool            `json:"enabled"`
	Desc     string          `json:"desc,omitempty"`
	Required []string        `json:"required,omitempty"`
	Lookup   *LookupDef      `json:"lookup,omitempty"`
	Response json.RawMessage `json:"response"`
}

// ActionNameRe bounds dynamic action names. It deliberately overlaps with
// the built-in namespace; Register wins for exact matches because the
// registry is consulted before the dynamic fallback.
var ActionNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Validate checks a definition before it is stored.
func (d *ActionDef) Validate() error {
	if !ActionNameRe.MatchString(d.Name) {
		return errors.New("invalid name: use 1-64 chars of [A-Za-z0-9._-], starting with alphanumeric")
	}
	if len(d.Response) == 0 {
		return errors.New("response template is required")
	}
	var probe any
	if err := json.Unmarshal(d.Response, &probe); err != nil {
		return fmt.Errorf("response is not valid JSON: %w", err)
	}
	if d.Lookup != nil {
		if d.Lookup.Key == "" {
			return errors.New("lookup.key is required when lookup is set")
		}
		for i, row := range d.Lookup.Rows {
			if row == nil {
				return fmt.Errorf("lookup.rows[%d] must be a JSON object", i)
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

// DynamicRouter adapts an ActionStore to the Handler contract so it can be
// installed as the registry fallback.
type DynamicRouter struct {
	Store *ActionStore
}

// Handle resolves req.Action against the store and renders the response.
func (r *DynamicRouter) Handle(ctx context.Context, req *Request) (*Response, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	if r.Store == nil {
		return errResp(req.ReqID, CodeNotFound, "action not found"), nil
	}
	def, ok := r.Store.Get(req.Action)
	if !ok || !def.Enabled {
		return errResp(req.ReqID, CodeNotFound, "action not found"), nil
	}
	return ExecuteAction(def, req.ReqID, req.Payload), nil
}

// EnableDynamicActions installs the store as the registry fallback, so
// runtime-defined actions are served alongside the built-in ones. Handlers
// registered with Registry.Register keep precedence on exact name matches.
func (s *Server) EnableDynamicActions(store *ActionStore) {
	s.registry.SetFallback((&DynamicRouter{Store: store}).Handle)
}

// ExecuteAction renders one action definition. It never returns a Go error:
// every failure is mapped onto a business code so the client sees a stable
// envelope (and the admin "试运行" panel can show the same result).
func ExecuteAction(def ActionDef, reqID string, payload json.RawMessage) *Response {
	fields := map[string]any{}
	if len(payload) > 0 && string(payload) != "null" {
		if err := json.Unmarshal(payload, &fields); err != nil {
			return errResp(reqID, CodeBadRequest, "payload must be a JSON object")
		}
	}

	for _, f := range def.Required {
		if _, ok := fields[f]; !ok {
			return errResp(reqID, CodeBadRequest, "missing required field: "+f)
		}
	}

	var row map[string]any
	if def.Lookup != nil {
		want, ok := fields[def.Lookup.Key]
		if !ok {
			return errResp(reqID, CodeBadRequest, "missing lookup key: "+def.Lookup.Key)
		}
		for _, candidate := range def.Lookup.Rows {
			if sameScalar(candidate[def.Lookup.Key], want) {
				row = candidate
				break
			}
		}
		if row == nil {
			return errResp(reqID, CodeNotFound, "no matching row")
		}
	}

	var tpl any
	if err := json.Unmarshal(def.Response, &tpl); err != nil {
		return errResp(reqID, CodeInternal, "invalid response template")
	}
	rendered := substitute(tpl, fields, row)
	data, err := json.Marshal(rendered)
	if err != nil {
		return errResp(reqID, CodeInternal, "render failed")
	}
	return okResp(reqID, data)
}

// sameScalar compares two JSON scalars by their canonical text form so that
// 10001 (number) and "10001" (string) match.
func sameScalar(a, b any) bool {
	if a == nil || b == nil {
		return a == b
	}
	return fmt.Sprint(a) == fmt.Sprint(b)
}

// ---------------------------------------------------------------------------
// Template rendering
// ---------------------------------------------------------------------------

var placeholderRe = regexp.MustCompile(`\$\{([^{}]+)\}`)

func substitute(v any, fields, row map[string]any) any {
	switch t := v.(type) {
	case string:
		return substituteString(t, fields, row)
	case []any:
		for i := range t {
			t[i] = substitute(t[i], fields, row)
		}
		return t
	case map[string]any:
		for k := range t {
			t[k] = substitute(t[k], fields, row)
		}
		return t
	default:
		return v
	}
}

func substituteString(s string, fields, row map[string]any) any {
	// Whole-string single placeholder: keep the raw JSON type.
	if m := placeholderRe.FindStringSubmatch(s); m != nil && m[0] == s {
		if v, ok := resolve(m[1], fields, row); ok {
			return v
		}
		return s // unresolved: leave verbatim so it is visible
	}
	// Embedded placeholders: stringify in place.
	return placeholderRe.ReplaceAllStringFunc(s, func(match string) string {
		inner := match[2 : len(match)-1]
		if v, ok := resolve(inner, fields, row); ok {
			return stringify(v)
		}
		return match
	})
}

// resolve walks a dotted path such as "payload.qq" or "row.roles".
func resolve(path string, fields, row map[string]any) (any, bool) {
	var root map[string]any
	switch {
	case strings.HasPrefix(path, "payload."):
		root = fields
		path = strings.TrimPrefix(path, "payload.")
	case strings.HasPrefix(path, "row."):
		root = row
		path = strings.TrimPrefix(path, "row.")
	default:
		// Bare name: look in the row first (the common case), then payload.
		if v, ok := dig(row, path); ok {
			return v, true
		}
		v, ok := dig(fields, path)
		return v, ok
	}
	if root == nil {
		return nil, false
	}
	return dig(root, path)
}

// dig descends into nested objects using a dotted path.
func dig(root map[string]any, path string) (any, bool) {
	if root == nil {
		return nil, false
	}
	parts := strings.Split(path, ".")
	var cur any = root
	for _, p := range parts {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[p]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

func stringify(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprint(v)
		}
		return string(b)
	}
}
