package appapi

import (
	"database/sql"
	"encoding/json"
	"sync"
	"time"

	// Pure-Go SQLite driver: keeps the build CGO-free so the binary still
	// cross-compiles to a static linux/amd64 executable.
	_ "modernc.org/sqlite"
)

// sqliteDriver is the database/sql driver name registered by modernc.org/sqlite.
const sqliteDriver = "sqlite"

// ActionStore persists runtime-defined actions in a single SQLite file.
//
// Schema (created on first open):
//
//	CREATE TABLE actions (
//	  name        TEXT PRIMARY KEY,
//	  enabled     INTEGER NOT NULL DEFAULT 1,
//	  desc        TEXT    NOT NULL DEFAULT '',
//	  required    TEXT    NOT NULL DEFAULT '[]',   -- JSON array of field names
//	  lookup_key  TEXT    NOT NULL DEFAULT '',     -- '' means "no lookup"
//	  lookup_rows TEXT    NOT NULL DEFAULT '[]',   -- JSON array of row objects
//	  response    TEXT    NOT NULL DEFAULT '{}',   -- JSON response template
//	  updated_at  TEXT    NOT NULL                 -- RFC3339 UTC
//	);
//
// One writer (the admin UI) and N readers (the appapi workers) are expected.
// The connection pool is pinned to a single connection, which serialises
// access and removes SQLITE_BUSY on the single-file database.
type ActionStore struct {
	mu   sync.RWMutex
	db   *sql.DB
	path string
}

// NewActionStore opens (creating if needed) the SQLite store at path.
func NewActionStore(path string) (*ActionStore, error) {
	db, err := sql.Open(sqliteDriver, path)
	if err != nil {
		return nil, err
	}
	// Single connection: this store is tiny and always single-process.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	s := &ActionStore{db: db, path: path}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Path returns the backing database file path.
func (s *ActionStore) Path() string { return s.path }

// Close releases the database handle.
func (s *ActionStore) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *ActionStore) migrate() error {
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA busy_timeout=5000",
	}
	for _, p := range pragmas {
		if _, err := s.db.Exec(p); err != nil {
			return err
		}
	}
	const schema = `
CREATE TABLE IF NOT EXISTS actions (
  name        TEXT PRIMARY KEY,
  enabled     INTEGER NOT NULL DEFAULT 1,
  desc        TEXT    NOT NULL DEFAULT '',
  required    TEXT    NOT NULL DEFAULT '[]',
  lookup_key  TEXT    NOT NULL DEFAULT '',
  lookup_rows TEXT    NOT NULL DEFAULT '[]',
  response    TEXT    NOT NULL DEFAULT '{}',
  updated_at  TEXT    NOT NULL
);`
	_, err := s.db.Exec(schema)
	return err
}

// List returns every definition ordered by name.
func (s *ActionStore) List() []ActionDef {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query(`SELECT name, enabled, desc, required, lookup_key, lookup_rows, response
	                         FROM actions ORDER BY name`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	out := make([]ActionDef, 0, 8)
	for rows.Next() {
		d, err := scanDef(rows)
		if err != nil {
			continue
		}
		out = append(out, d)
	}
	_ = rows.Err()
	return out
}

// Get returns a definition by name.
func (s *ActionStore) Get(name string) (ActionDef, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	row := s.db.QueryRow(`SELECT name, enabled, desc, required, lookup_key, lookup_rows, response
	                      FROM actions WHERE name = ?`, name)
	d, err := scanDef(row)
	if err != nil {
		return ActionDef{}, false
	}
	return d, true
}

// Put validates and upserts a definition.
func (s *ActionStore) Put(d ActionDef) error {
	if err := d.Validate(); err != nil {
		return err
	}

	required, err := json.Marshal(d.Required)
	if err != nil || d.Required == nil {
		required = []byte("[]")
	}
	lookupKey := ""
	lookupRows := []byte("[]")
	if d.Lookup != nil {
		lookupKey = d.Lookup.Key
		if b, e := json.Marshal(d.Lookup.Rows); e == nil {
			lookupRows = b
		}
	}
	response := d.Response
	if len(response) == 0 {
		response = []byte("{}")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.db.Exec(`
INSERT INTO actions (name, enabled, desc, required, lookup_key, lookup_rows, response, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(name) DO UPDATE SET
  enabled     = excluded.enabled,
  desc        = excluded.desc,
  required    = excluded.required,
  lookup_key  = excluded.lookup_key,
  lookup_rows = excluded.lookup_rows,
  response    = excluded.response,
  updated_at  = excluded.updated_at`,
		d.Name,
		boolToInt(d.Enabled),
		d.Desc,
		string(required),
		lookupKey,
		string(lookupRows),
		string(response),
		time.Now().UTC().Format(time.RFC3339),
	)
	return err
}

// Delete removes a definition. Deleting an unknown name is not an error.
func (s *ActionStore) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM actions WHERE name = ?`, name)
	return err
}

// scanner is satisfied by both *sql.Row and *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

func scanDef(sc scanner) (ActionDef, error) {
	var (
		d        ActionDef
		enabled  int
		required string
		lookupK  string
		lookupR  string
		response string
	)
	if err := sc.Scan(&d.Name, &enabled, &d.Desc, &required, &lookupK, &lookupR, &response); err != nil {
		return ActionDef{}, err
	}
	d.Enabled = enabled != 0
	if err := json.Unmarshal([]byte(required), &d.Required); err != nil {
		d.Required = nil
	}
	if lookupK != "" {
		var rows []map[string]any
		if err := json.Unmarshal([]byte(lookupR), &rows); err != nil {
			rows = nil
		}
		d.Lookup = &LookupDef{Key: lookupK, Rows: rows}
	}
	if response == "" {
		response = "{}"
	}
	d.Response = json.RawMessage(response)
	return d, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
