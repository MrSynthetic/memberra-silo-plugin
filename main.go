// Memberra plugin for Silo: an outbound, signed connection that lets Memberra
// manage customer accounts on this Silo server without the Memberra agent.
package main

import (
	"context"
	_ "embed"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	sdkruntime "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/runtime"
	"github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/runtimehost"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/MrSynthetic/memberra/plugins/silo/internal/bridge"
	"github.com/MrSynthetic/memberra/plugins/silo/internal/memberra"
	"github.com/MrSynthetic/memberra/plugins/silo/internal/silo"
)

//go:embed manifest.json
var manifestJSON []byte

// version is set by the release build (-ldflags "-X main.version=...").
var version = "1.0.2"

type hostStore struct{ c *runtimehost.Client }

func (h hostStore) Read(ctx context.Context, key string) ([]byte, bool, error) {
	return h.c.ReadInstanceState(ctx, key)
}
func (h hostStore) Write(ctx context.Context, key string, value []byte) error {
	return h.c.WriteInstanceState(ctx, key, value)
}

func parseConfig(entries []*pluginv1.ConfigEntry) bridge.Config {
	cfg := bridge.Config{MemberraURL: "https://memberra.co.uk", SiloURL: "http://127.0.0.1:8090"}
	for _, e := range entries {
		if e.GetKey() != "connection" {
			continue
		}
		v := e.GetValue().AsMap()
		get := func(k string) string { s, _ := v[k].(string); return strings.TrimSpace(s) }
		if s := get("memberra_url"); s != "" {
			cfg.MemberraURL = s
		}
		if s := get("silo_url"); s != "" {
			cfg.SiloURL = s
		}
		cfg.PairingCode = get("pairing_code")
		cfg.SiloAPIKey = get("silo_api_key")
	}
	return cfg
}

// connectionTask is the scheduled task: Silo runs it at startup (its default
// trigger), which starts the plugin and its connection loop; later runs act
// as a watchdog and report status in Silo's task history.
type connectionTask struct {
	pluginv1.UnimplementedScheduledTaskServer
	b *bridge.Bridge
}

func (t *connectionTask) Run(ctx context.Context, _ *pluginv1.RunScheduledTaskRequest) (*pluginv1.RunScheduledTaskResponse, error) {
	t.b.EnsureRunning()
	s := t.b.Status()
	out, err := structpb.NewStruct(map[string]any{
		"running":   s.Running,
		"paired":    s.Paired,
		"lastError": s.LastError,
		"lastHeartbeat": func() string {
			if s.LastHeartbeat.IsZero() {
				return ""
			}
			return s.LastHeartbeat.UTC().Format(time.RFC3339)
		}(),
	})
	if err != nil {
		return nil, err
	}
	return &pluginv1.RunScheduledTaskResponse{Output: out}, nil
}

// checks implements Check connection on the settings page.
type checks struct {
	pluginv1.UnimplementedConfigurationChecksServer
}

func (checks) TestConfiguration(ctx context.Context, req *pluginv1.TestConfigurationRequest) (*pluginv1.TestConfigurationResponse, error) {
	cfg := parseConfig(req.GetConfig())
	fail := func(msg string) (*pluginv1.TestConfigurationResponse, error) {
		return &pluginv1.TestConfigurationResponse{Ok: false, Message: msg}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if cfg.SiloAPIKey == "" {
		return fail("Add a Silo admin API key.")
	}
	if err := silo.New(cfg.SiloURL, cfg.SiloAPIKey).Test(ctx); err != nil {
		return fail(err.Error() + ".")
	}
	if _, err := bridge.ServerInfo(ctx, cfg.SiloURL, version); err != nil {
		return fail(fmt.Sprintf("Silo URL %s: %v.", cfg.SiloURL, err))
	}
	if _, err := memberra.New(cfg.MemberraURL); err != nil {
		return fail(err.Error() + ".")
	}
	return &pluginv1.TestConfigurationResponse{Ok: true}, nil
}

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	b := &bridge.Bridge{
		PluginVersion: version,
		Log:           log,
		Store: func() bridge.Store {
			if h := sdkruntime.Host(); h != nil {
				return hostStore{h}
			}
			return nil
		},
	}
	sdkruntime.ServeManifestWithOptions(manifestJSON, version,
		sdkruntime.CapabilityServers{ScheduledTask: &connectionTask{b: b}},
		sdkruntime.WithConfigurationChecks(checks{}),
		sdkruntime.WithConfigure(func(_ context.Context, entries []*pluginv1.ConfigEntry) error {
			// Store whatever arrived; report problems from the loop and checks.
			b.Configure(parseConfig(entries))
			b.EnsureRunning()
			return nil
		}),
	)
}
