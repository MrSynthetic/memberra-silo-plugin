package bridge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/MrSynthetic/memberra/plugins/silo/internal/memberra"
	"github.com/MrSynthetic/memberra/plugins/silo/internal/silo"
)

// Config is the plugin's settings form.
type Config struct {
	MemberraURL string
	PairingCode string
	SiloURL     string
	SiloAPIKey  string
}

// Store persists the install credentials (Silo's encrypted instance state).
type Store interface {
	Read(ctx context.Context, key string) ([]byte, bool, error)
	Write(ctx context.Context, key string, value []byte) error
}

const stateKey = "memberra.install"

type savedState struct {
	memberra.Credentials
	// PairedWith is a hash of the pairing code that produced these
	// credentials, so entering a new code re-pairs and the old one is not
	// redeemed twice.
	PairedWith string `json:"pairedWith"`
	BaseURL    string `json:"baseUrl"`
}

// Status is what the scheduled task and settings check report.
type Status struct {
	Running       bool      `json:"running"`
	Paired        bool      `json:"paired"`
	LastHeartbeat time.Time `json:"lastHeartbeat,omitzero"`
	LastError     string    `json:"lastError,omitempty"`
}

// Bridge owns the connection loop.
type Bridge struct {
	PluginVersion string
	Store         func() Store // nil until the host is bound
	Log           *slog.Logger
	Interval      time.Duration

	mu        sync.Mutex
	cfg       Config
	libraries []memberra.Library // last good list, reused if a read fails
	running   bool
	status    Status
	wake      chan struct{}
}

// Configure stores new settings and wakes the loop.
func (b *Bridge) Configure(cfg Config) {
	b.mu.Lock()
	b.cfg = cfg
	b.mu.Unlock()
	b.poke()
}

func (b *Bridge) poke() {
	b.mu.Lock()
	wake := b.wake
	b.mu.Unlock()
	if wake != nil {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
}

// Status returns a snapshot.
func (b *Bridge) Status() Status {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.status
	s.Running = b.running
	return s
}

// EnsureRunning starts the loop once per process.
func (b *Bridge) EnsureRunning() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.running {
		return
	}
	b.running = true
	b.wake = make(chan struct{}, 1)
	go b.loop(context.Background())
}

func (b *Bridge) setStatus(fn func(*Status)) {
	b.mu.Lock()
	fn(&b.status)
	b.mu.Unlock()
}

func (b *Bridge) logger() *slog.Logger {
	if b.Log != nil {
		return b.Log
	}
	return slog.Default()
}

func (b *Bridge) loop(ctx context.Context) {
	interval := b.Interval
	if interval <= 0 {
		interval = 10 * time.Second
	}
	delay := time.Duration(0)
	for {
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-b.wake:
				timer.Stop()
			case <-ctx.Done():
				timer.Stop()
				return
			}
		}
		err := b.Tick(ctx)
		if err != nil {
			b.setStatus(func(s *Status) { s.LastError = err.Error() })
			b.logger().Warn("memberra connection", "error", err)
			// Back off on errors: 10s, 20s, 40s, capped at 2 minutes.
			if delay < interval {
				delay = interval
			} else {
				delay = min(delay*2, 2*time.Minute)
			}
			continue
		}
		b.setStatus(func(s *Status) { s.LastError = "" })
		delay = interval
	}
}

func hashCode(code string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(code)))
	return hex.EncodeToString(sum[:])
}

func (b *Bridge) load(ctx context.Context) (*savedState, error) {
	if b.Store == nil || b.Store() == nil {
		return nil, errors.New("plugin host not ready")
	}
	raw, ok, err := b.Store().Read(ctx, stateKey)
	if err != nil || !ok {
		return nil, err
	}
	var s savedState
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, nil // unreadable state: pair again
	}
	return &s, nil
}

func (b *Bridge) save(ctx context.Context, s *savedState) error {
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return b.Store().Write(ctx, stateKey, raw)
}

// ServerInfo reads this server's identity from Silo's public endpoints.
func ServerInfo(ctx context.Context, siloURL, pluginVersion string) (memberra.ServerInfo, error) {
	info := memberra.ServerInfo{ServerName: "Silo", PluginVersion: pluginVersion, Capabilities: Capabilities}
	get := func(path string, out any) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(siloURL, "/")+path, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/json")
		res, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
		if err != nil {
			return err
		}
		defer res.Body.Close()
		if res.StatusCode >= 300 {
			return errors.New(res.Status)
		}
		return json.NewDecoder(res.Body).Decode(out)
	}
	var identity struct {
		ServerID string `json:"server_id"`
	}
	if err := get("/api/v2/system/identity", &identity); err != nil || identity.ServerID == "" {
		return info, errors.New("could not read this Silo server's identity")
	}
	var system struct {
		ServerVersion string `json:"server_version"`
	}
	_ = get("/api/v2/system/info", &system)
	info.ServerID = identity.ServerID
	info.ServerVersion = system.ServerVersion
	if info.ServerVersion == "" {
		info.ServerVersion = "unknown"
	}
	return info, nil
}

// Tick runs one pair/heartbeat/execute cycle.
func (b *Bridge) Tick(ctx context.Context) error {
	b.mu.Lock()
	cfg := b.cfg
	b.mu.Unlock()
	if cfg.SiloAPIKey == "" || cfg.MemberraURL == "" {
		return errors.New("settings incomplete: add the Silo admin API key")
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	mc, err := memberra.New(cfg.MemberraURL)
	if err != nil {
		return err
	}
	sc := silo.New(cfg.SiloURL, cfg.SiloAPIKey)
	info, err := ServerInfo(ctx, cfg.SiloURL, b.PluginVersion)
	if err != nil {
		return err
	}

	state, err := b.load(ctx)
	if err != nil {
		return err
	}
	code := strings.TrimSpace(cfg.PairingCode)
	needsPairing := state == nil || state.InstallToken == "" || state.BaseURL != mc.BaseURL ||
		(code != "" && state.PairedWith != hashCode(code))
	if needsPairing {
		// A code is single use: after a revoke, the code that paired last time
		// can't pair again.
		usedCode := state != nil && state.InstallToken == "" && state.PairedWith == hashCode(code)
		if code == "" || usedCode {
			b.setStatus(func(s *Status) { s.Paired = false })
			return errors.New("not paired: paste a new pairing code from Memberra")
		}
		creds, err := mc.Register(ctx, code, info)
		if err != nil {
			return err
		}
		state = &savedState{Credentials: *creds, PairedWith: hashCode(code), BaseURL: mc.BaseURL}
		if err := b.save(ctx, state); err != nil {
			return err
		}
		b.logger().Info("paired with Memberra", "install", creds.InstallID)
	}
	b.setStatus(func(s *Status) { s.Paired = true })

	// Libraries are informational: a failed read must not stop the heartbeat
	// that delivers account commands.
	b.mu.Lock()
	reported := b.libraries
	b.mu.Unlock()
	if libs, err := sc.ListLibraries(ctx); err != nil {
		b.logger().Warn("could not read libraries; reporting the last known list", "error", err)
	} else {
		reported = make([]memberra.Library, 0, len(libs))
		for _, l := range libs {
			reported = append(reported, memberra.Library{ID: l.ID, Name: l.Name, Kind: l.Kind})
		}
		b.mu.Lock()
		b.libraries = reported
		b.mu.Unlock()
	}

	commands, err := mc.Heartbeat(ctx, &state.Credentials, info, reported)
	if errors.Is(err, memberra.ErrUnauthorized) {
		// Revoked in Memberra. Forget the token; a new pairing code re-pairs.
		_ = b.save(ctx, &savedState{PairedWith: state.PairedWith, BaseURL: state.BaseURL})
		b.setStatus(func(s *Status) { s.Paired = false })
		return err
	}
	if err != nil {
		return err
	}
	b.setStatus(func(s *Status) { s.LastHeartbeat = time.Now() })

	for _, cmd := range commands {
		result, runErr := Execute(ctx, sc, cmd)
		if runErr != nil {
			b.logger().Warn("command failed", "type", cmd.Type, "id", cmd.ID, "error", runErr)
		}
		if err := mc.Ack(ctx, &state.Credentials, cmd.ID, runErr, result); err != nil {
			return err
		}
	}
	return nil
}
