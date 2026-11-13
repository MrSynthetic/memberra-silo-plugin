package memberra

import "testing"

// The same input signed by Memberra's server code
// (src/lib/jellyfin-plugin/request-signing.server.ts).
func TestSignMatchesServer(t *testing.T) {
	got := Sign("tok_abcdefghijklmnopqrstuvwxyz012345", "post",
		"/api/public/jellyfin-plugin/heartbeat", "1763035200000", "nonce_123456789",
		[]byte(`{"serverName":"Silo","libraries":[]}`))
	const want = "sS31CPmFE6EaoNp5AX0pUW-bvJf9ZUVoYehWjEB0ip0"
	if got != want {
		t.Fatalf("signature %q, server computes %q", got, want)
	}
}

func TestNewRequiresHTTPS(t *testing.T) {
	for _, bad := range []string{"http://memberra.co.uk", "ftp://x", "not a url", ""} {
		if _, err := New(bad); err == nil {
			t.Errorf("New(%q) accepted", bad)
		}
	}
	for _, ok := range []string{"https://memberra.co.uk/", "http://127.0.0.1:3000"} {
		if _, err := New(ok); err != nil {
			t.Errorf("New(%q): %v", ok, err)
		}
	}
}
