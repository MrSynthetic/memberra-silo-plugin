package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/MrSynthetic/memberra/plugins/silo/internal/memberra"
)

// ---- fake Silo: enforces ETags, unknown create fields and admin accounts ----

type fakeSilo struct {
	mu       sync.Mutex
	users    map[string]map[string]any
	versions map[string]int
	sessions map[string]int
	nextID   int
	writes   []string

	librariesDown bool
	scopedKey     bool // key scoped to admin:users: no login-sessions route
}

func newFakeSilo() *fakeSilo {
	return &fakeSilo{
		users: map[string]map[string]any{
			"1": {"id": "1", "username": "owner", "role": "admin", "is_owner": true, "enabled": true},
			"2": {"id": "2", "username": "alice", "role": "user", "enabled": true, "library_ids": nil},
		},
		versions: map[string]int{"1": 1, "2": 1},
		sessions: map[string]int{"1": 1, "2": 2},
		nextID:   10,
	}
}

func (f *fakeSilo) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	reply := func(status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if v != nil {
			_ = json.NewEncoder(w).Encode(v)
		}
	}
	switch r.URL.Path {
	case "/api/v2/system/identity":
		reply(200, map[string]any{"server_id": "silo-test-server"})
		return
	case "/api/v2/system/info":
		reply(200, map[string]any{"server_version": "test"})
		return
	}
	if r.Header.Get("Authorization") != "Bearer silo-key" {
		reply(401, map[string]any{"error": "unauthorized"})
		return
	}
	// Like a key scoped to admin:users + libraries:read: the admin library
	// route is refused, the account's library list is allowed.
	if r.URL.Path == "/api/v2/libraries" {
		reply(403, map[string]any{"detail": "API key scopes do not permit this route"})
		return
	}
	if r.URL.Path == "/api/v2/user/libraries" {
		if f.librariesDown {
			reply(500, map[string]any{"error": "down"})
			return
		}
		reply(200, map[string]any{"items": []map[string]any{{"id": "1", "name": "Movies", "type": "movies"}}})
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/v2/admin/users")
	if rest == "" {
		if r.Method == http.MethodGet {
			items := []map[string]any{}
			for _, u := range f.users {
				items = append(items, u)
			}
			reply(200, map[string]any{"items": items, "page": map[string]any{"has_more": false}})
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if _, bad := body["enabled"]; bad {
			reply(422, map[string]any{"errors": []any{map[string]any{"location": "body.enabled", "code": "unknown_field"}}})
			return
		}
		id := strconv.Itoa(f.nextID)
		f.nextID++
		delete(body, "password")
		body["id"], body["enabled"] = id, true
		f.users[id], f.versions[id] = body, 1
		f.writes = append(f.writes, "POST "+id)
		reply(201, map[string]any{"id": id})
		return
	}
	parts := strings.Split(strings.TrimPrefix(rest, "/"), "/")
	id := parts[0]
	u, ok := f.users[id]
	if !ok {
		reply(404, map[string]any{"error": "not found"})
		return
	}
	if len(parts) == 2 && parts[1] == "login-sessions" && r.Method == http.MethodDelete {
		if f.scopedKey {
			reply(403, map[string]any{"detail": "API key scopes do not permit this route"})
			return
		}
		f.sessions[id] = 0
		reply(204, nil)
		return
	}
	etag := fmt.Sprintf(`"v%d"`, f.versions[id])
	if r.Method == http.MethodGet {
		w.Header().Set("ETag", etag)
		reply(200, u)
		return
	}
	if r.Header.Get("If-Match") != etag {
		reply(412, map[string]any{"error": "precondition failed"})
		return
	}
	switch r.Method {
	case http.MethodPut:
		var patch map[string]any
		_ = json.NewDecoder(r.Body).Decode(&patch)
		delete(patch, "password")
		for k, v := range patch {
			u[k] = v
		}
		f.versions[id]++
		f.writes = append(f.writes, "PUT "+id)
		reply(200, u)
	case http.MethodDelete:
		delete(f.users, id)
		f.writes = append(f.writes, "DELETE "+id)
		reply(204, nil)
	}
}

// ---- fake Memberra: pairing, signed heartbeats, acks ----

type fakeMemberra struct {
	mu       sync.Mutex
	token    string
	revoked  bool
	queue    []memberra.Command
	acks     []map[string]any
	pairings int
	unsigned int
}

func (m *fakeMemberra) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	var payload map[string]any
	_ = json.Unmarshal(body, &payload)
	if r.URL.Path == "/api/public/jellyfin-plugin/register" {
		if payload["pairingCode"] != "PAIR-CODE-1" || payload["provider"] != "silo" || payload["serverId"] != "silo-test-server" {
			w.WriteHeader(401)
			return
		}
		m.pairings++
		m.token, m.revoked = "install-token-abcdefghijklmnop", false
		_ = json.NewEncoder(w).Encode(map[string]any{"installId": "00000000-0000-0000-0000-0000000000aa", "installToken": m.token})
		return
	}
	auth := r.Header.Get("Authorization")
	sig := memberra.Sign(m.token, r.Method, r.URL.Path, r.Header.Get("X-Memberra-Timestamp"), r.Header.Get("X-Memberra-Nonce"), body)
	if m.revoked || auth != "Bearer 00000000-0000-0000-0000-0000000000aa."+m.token || sig != r.Header.Get("X-Memberra-Signature") {
		m.unsigned++
		w.WriteHeader(401)
		return
	}
	switch r.URL.Path {
	case "/api/public/jellyfin-plugin/heartbeat":
		cmds := m.queue
		m.queue = nil
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "commands": cmds})
	case "/api/public/jellyfin-plugin/command-ack":
		m.acks = append(m.acks, payload)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}
}

type memStore struct{ m map[string][]byte }

func (s *memStore) Read(_ context.Context, k string) ([]byte, bool, error) {
	v, ok := s.m[k]
	return v, ok, nil
}
func (s *memStore) Write(_ context.Context, k string, v []byte) error { s.m[k] = v; return nil }

type rig struct {
	silo  *fakeSilo
	mem   *fakeMemberra
	b     *Bridge
	store *memStore
}

func newRig(t *testing.T) *rig {
	t.Helper()
	fs, fm := newFakeSilo(), &fakeMemberra{}
	ss, ms := httptest.NewServer(fs), httptest.NewServer(fm)
	t.Cleanup(ss.Close)
	t.Cleanup(ms.Close)
	store := &memStore{m: map[string][]byte{}}
	b := &Bridge{PluginVersion: "test", Store: func() Store { return store }}
	b.Configure(Config{MemberraURL: ms.URL, PairingCode: "PAIR-CODE-1", SiloURL: ss.URL, SiloAPIKey: "silo-key"})
	return &rig{silo: fs, mem: fm, b: b, store: store}
}

func (r *rig) run(t *testing.T, cmds ...memberra.Command) []map[string]any {
	t.Helper()
	r.mem.mu.Lock()
	r.mem.queue, r.mem.acks = cmds, nil
	r.mem.mu.Unlock()
	if err := r.b.Tick(context.Background()); err != nil {
		t.Fatalf("tick: %v", err)
	}
	return r.mem.acks
}

func cmd(id, typ string, payload map[string]any) memberra.Command {
	return memberra.Command{ID: id, Type: typ, Payload: payload}
}

func TestPairsOnceThenSignsEveryRequest(t *testing.T) {
	r := newRig(t)
	r.run(t)
	r.run(t)
	if r.mem.pairings != 1 {
		t.Fatalf("paired %d times, want 1", r.mem.pairings)
	}
	if r.mem.unsigned != 0 {
		t.Fatalf("%d requests failed signature checks", r.mem.unsigned)
	}
	if !r.b.Status().Paired {
		t.Fatal("not reported as paired")
	}
}

func TestProvisionLifecycle(t *testing.T) {
	r := newRig(t)
	acks := r.run(t, cmd("c1", "provision_user", map[string]any{"username": "bob", "libraries": []any{"1"}, "password": "Temp-password-1"}))
	if acks[0]["status"] != "succeeded" {
		t.Fatalf("provision: %v", acks[0])
	}
	id := acks[0]["result"].(map[string]any)["providerUserId"].(string)
	if got := r.silo.users[id]["library_ids"]; fmt.Sprint(got) != "[1]" {
		t.Fatalf("libraries %v", got)
	}

	// A retried provision finds the same account.
	acks = r.run(t, cmd("c2", "provision_user", map[string]any{"username": "BOB", "libraries": []any{}}))
	if acks[0]["result"].(map[string]any)["providerUserId"] != id || r.silo.users[id]["library_ids"] != nil {
		t.Fatalf("retry: %v / libraries %v", acks[0], r.silo.users[id]["library_ids"])
	}

	acks = r.run(t,
		cmd("c3", "suspend_user", map[string]any{"userId": id}),
		cmd("c4", "apply_entitlements", map[string]any{"userId": id, "patch": map[string]any{"max_streams": float64(2), "transcode_allowed": false}}),
		cmd("c5", "rename_user", map[string]any{"userId": id, "username": "bobby"}),
		cmd("c6", "reset_password", map[string]any{"userId": id, "password": "New-password-1"}),
		cmd("c7", "restore_user", map[string]any{"userId": id, "libraries": []any{"1"}}),
	)
	for _, a := range acks {
		if a["status"] != "succeeded" {
			t.Fatalf("%v", a)
		}
	}
	u := r.silo.users[id]
	if u["enabled"] != true || u["username"] != "bobby" || u["max_streams"] != float64(2) || u["transcode_allowed"] != false {
		t.Fatalf("account after updates: %v", u)
	}
	if r.silo.sessions[id] != 0 {
		t.Fatal("sessions not revoked")
	}

	acks = r.run(t, cmd("c8", "delete_user", map[string]any{"userId": id}), cmd("c9", "delete_user", map[string]any{"userId": id}))
	if acks[0]["status"] != "succeeded" || acks[1]["status"] != "succeeded" {
		t.Fatalf("delete: %v", acks)
	}
	if _, exists := r.silo.users[id]; exists {
		t.Fatal("not deleted")
	}
}

func TestNeverTouchesAdmins(t *testing.T) {
	r := newRig(t)
	acks := r.run(t,
		cmd("a1", "suspend_user", map[string]any{"userId": "1"}),
		cmd("a2", "delete_user", map[string]any{"userId": "1"}),
		cmd("a3", "provision_user", map[string]any{"username": "owner"}),
		cmd("a4", "reset_password", map[string]any{"userId": "1", "password": "Takeover-123"}),
	)
	for _, a := range acks {
		if a["status"] != "failed" {
			t.Fatalf("admin command succeeded: %v", a)
		}
	}
	if len(r.silo.writes) != 0 {
		t.Fatalf("admin account was written: %v", r.silo.writes)
	}
}

func TestRejectsUnsafeInput(t *testing.T) {
	r := newRig(t)
	acks := r.run(t,
		cmd("b1", "apply_entitlements", map[string]any{"userId": "2", "patch": map[string]any{"role": "admin"}}),
		cmd("b2", "provision_user", map[string]any{"username": "../../etc"}),
		cmd("b3", "run_shell", map[string]any{"cmd": "id"}),
		cmd("b4", "reset_password", map[string]any{"userId": "2", "password": "short"}),
	)
	for _, a := range acks {
		if a["status"] != "failed" {
			t.Fatalf("unsafe command succeeded: %v", a)
		}
	}
	if r.silo.users["2"]["role"] != "user" || len(r.silo.writes) != 0 {
		t.Fatalf("unsafe write happened: %v", r.silo.writes)
	}
}

func TestListUsersMarksAdmins(t *testing.T) {
	r := newRig(t)
	acks := r.run(t, cmd("l1", "list_users", nil))
	rows := acks[0]["result"].(map[string]any)["users"].([]any)
	admins := 0
	for _, row := range rows {
		if row.(map[string]any)["isAdministrator"] == true {
			admins++
		}
	}
	if len(rows) != 2 || admins != 1 {
		t.Fatalf("rows %v", rows)
	}
}

func TestRevokeStopsUntilNewCode(t *testing.T) {
	r := newRig(t)
	r.run(t)
	r.mem.revoked = true
	if err := r.b.Tick(context.Background()); err == nil {
		t.Fatal("revoked install kept working")
	}
	// The used code must not be redeemed again.
	if err := r.b.Tick(context.Background()); err == nil || !strings.Contains(err.Error(), "new pairing code") {
		t.Fatalf("want a new-code error, got %v", err)
	}
	if r.mem.pairings != 1 {
		t.Fatalf("re-redeemed the used code (%d pairings)", r.mem.pairings)
	}
}

func TestIncompleteSettingsDoNotCrash(t *testing.T) {
	b := &Bridge{Store: func() Store { return &memStore{m: map[string][]byte{}} }}
	b.Configure(Config{MemberraURL: "https://memberra.co.uk"})
	if err := b.Tick(context.Background()); err == nil {
		t.Fatal("expected a settings error")
	}
}

func TestHeartbeatSurvivesLibraryFailure(t *testing.T) {
	r := newRig(t)
	r.run(t) // caches the library list
	r.silo.librariesDown = true
	acks := r.run(t, cmd("h1", "suspend_user", map[string]any{"userId": "2"}))
	if len(acks) != 1 || acks[0]["status"] != "succeeded" {
		t.Fatalf("commands stopped when libraries failed: %v", acks)
	}
	if len(r.b.libraries) != 1 {
		t.Fatalf("lost the cached library list: %v", r.b.libraries)
	}
}

// With a key scoped to admin:users, Silo refuses the login-sessions route; it
// already ends a disabled account's sessions itself, so suspend must succeed.
func TestSuspendWithScopedKey(t *testing.T) {
	r := newRig(t)
	r.silo.scopedKey = true
	acks := r.run(t,
		cmd("s1", "suspend_user", map[string]any{"userId": "2"}),
		cmd("s2", "reset_password", map[string]any{"userId": "2", "password": "New-password-1"}),
	)
	for _, a := range acks {
		if a["status"] != "succeeded" {
			t.Fatalf("%v", a)
		}
	}
	if r.silo.users["2"]["enabled"] != false {
		t.Fatal("not suspended")
	}
}
