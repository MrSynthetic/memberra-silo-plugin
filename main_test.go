package main

import (
	"testing"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	publicmanifest "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/manifest"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestManifestLoads(t *testing.T) {
	m, err := publicmanifest.Load(manifestJSON)
	if err != nil {
		t.Fatal(err)
	}
	if m.GetPluginId() != "memberra.silo" || len(m.GetCapabilities()) != 1 {
		t.Fatalf("manifest %v", m)
	}
	secrets := 0
	for _, f := range m.GetGlobalConfigSchema()[0].GetAdminForm().GetFields() {
		if f.GetControl() == pluginv1.AdminFormControl_ADMIN_FORM_CONTROL_UNSPECIFIED {
			t.Errorf("field %s has no control", f.GetKey())
		}
		if f.GetSecret() {
			secrets++
		}
	}
	if secrets != 2 {
		t.Fatalf("want pairing code and API key secret, got %d secrets", secrets)
	}
}

func TestParseConfigDefaults(t *testing.T) {
	v, _ := structpb.NewStruct(map[string]any{"silo_api_key": " key ", "pairing_code": "CODE"})
	cfg := parseConfig([]*pluginv1.ConfigEntry{{Key: "connection", Value: v}})
	if cfg.MemberraURL != "https://memberra.co.uk" || cfg.SiloURL != "http://127.0.0.1:8090" || cfg.SiloAPIKey != "key" || cfg.PairingCode != "CODE" {
		t.Fatalf("%+v", cfg)
	}
	if empty := parseConfig(nil); empty.SiloAPIKey != "" || empty.MemberraURL == "" {
		t.Fatalf("%+v", empty)
	}
}
