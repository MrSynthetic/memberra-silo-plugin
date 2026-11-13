// Package memberra speaks Memberra's media-plugin protocol (shared with the
// Memberra Jellyfin plugin): one-time pairing, then signed heartbeats that
// carry queued commands, and signed acknowledgements.
//
// Every request after pairing carries
//
//	Authorization: Bearer <installId>.<installToken>
//	X-Memberra-Timestamp: <unix ms>
//	X-Memberra-Nonce: <random, single use>
//	X-Memberra-Signature: base64url(HMAC-SHA256(installToken,
//	    METHOD \n PATH \n TIMESTAMP \n NONCE \n hex(SHA256(body))))
package memberra

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ProtocolVersion is the signed-request protocol (v4) with Silo commands.
const ProtocolVersion = 4

const (
	registerPath  = "/api/public/jellyfin-plugin/register"
	heartbeatPath = "/api/public/jellyfin-plugin/heartbeat"
	ackPath       = "/api/public/jellyfin-plugin/command-ack"
)

// ErrUnauthorized means Memberra no longer accepts this install (revoked).
var ErrUnauthorized = errors.New("memberra rejected the install token; pair again")

// Credentials identify a paired install.
type Credentials struct {
	InstallID     string `json:"installId"`
	InstallToken  string `json:"installToken"`
	MediaServerID string `json:"mediaServerId,omitempty"`
}

// ServerInfo describes this Silo server.
type ServerInfo struct {
	ServerID      string
	ServerName    string
	ServerVersion string
	PluginVersion string
	Capabilities  map[string]bool
}

// Library is reported in each heartbeat.
type Library struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind,omitempty"`
}

// Command is one queued Memberra command.
type Command struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	Payload   map[string]any `json:"payload"`
	ExpiresAt string         `json:"expiresAt"`
}

// Client talks to one Memberra deployment.
type Client struct {
	BaseURL string
	HTTP    *http.Client
	Now     func() time.Time
}

// New returns a client for baseURL (https only, except for loopback testing).
func New(baseURL string) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid Memberra URL %q", baseURL)
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname())) {
		return nil, fmt.Errorf("the Memberra URL must use https")
	}
	return &Client{BaseURL: u.String(), HTTP: &http.Client{Timeout: 20 * time.Second}, Now: time.Now}, nil
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// Sign returns the request signature (exported for tests).
func Sign(token, method, path, timestamp, nonce string, body []byte) string {
	bodyHash := sha256.Sum256(body)
	canonical := strings.Join([]string{strings.ToUpper(method), path, timestamp, nonce, hex.EncodeToString(bodyHash[:])}, "\n")
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func newNonce() (string, error) {
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func (c *Client) post(ctx context.Context, path string, creds *Credentials, payload any, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Memberra-Silo-Plugin")
	if creds != nil {
		nonce, err := newNonce()
		if err != nil {
			return err
		}
		ts := strconv.FormatInt(c.Now().UnixMilli(), 10)
		req.Header.Set("Authorization", "Bearer "+creds.InstallID+"."+creds.InstallToken)
		req.Header.Set("X-Memberra-Timestamp", ts)
		req.Header.Set("X-Memberra-Nonce", nonce)
		req.Header.Set("X-Memberra-Signature", Sign(creds.InstallToken, http.MethodPost, path, ts, nonce, body))
	}
	res, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if res.StatusCode == http.StatusUnauthorized && creds != nil {
		return ErrUnauthorized
	}
	if res.StatusCode >= 300 {
		var problem struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &problem)
		if problem.Error == "" {
			problem.Error = strings.TrimSpace(string(raw))
		}
		return fmt.Errorf("memberra %s returned HTTP %d: %s", path, res.StatusCode, problem.Error)
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// Register redeems a one-time pairing code.
func (c *Client) Register(ctx context.Context, pairingCode string, info ServerInfo) (*Credentials, error) {
	var out Credentials
	err := c.post(ctx, registerPath, nil, map[string]any{
		"provider":        "silo",
		"pairingCode":     strings.TrimSpace(pairingCode),
		"serverId":        info.ServerID,
		"serverName":      info.ServerName,
		"serverVersion":   info.ServerVersion,
		"jellyfinVersion": info.ServerVersion, // legacy field name, kept for older backends
		"pluginVersion":   info.PluginVersion,
		"protocolVersion": ProtocolVersion,
		"capabilities":    info.Capabilities,
	}, &out)
	if err != nil {
		return nil, err
	}
	if out.InstallID == "" || out.InstallToken == "" {
		return nil, errors.New("memberra returned no install credentials")
	}
	return &out, nil
}

// Heartbeat reports health and returns queued commands.
func (c *Client) Heartbeat(ctx context.Context, creds *Credentials, info ServerInfo, libraries []Library) ([]Command, error) {
	if libraries == nil {
		libraries = []Library{}
	}
	var out struct {
		Commands []Command `json:"commands"`
	}
	err := c.post(ctx, heartbeatPath, creds, map[string]any{
		"provider":        "silo",
		"serverName":      info.ServerName,
		"serverVersion":   info.ServerVersion,
		"jellyfinVersion": info.ServerVersion,
		"pluginVersion":   info.PluginVersion,
		"protocolVersion": ProtocolVersion,
		"capabilities":    info.Capabilities,
		"libraries":       libraries,
	}, &out)
	return out.Commands, err
}

// Ack reports a command's outcome. result must not contain secrets.
func (c *Client) Ack(ctx context.Context, creds *Credentials, commandID string, err error, result map[string]any) error {
	body := map[string]any{"commandId": commandID, "status": "succeeded", "result": result}
	if result == nil {
		body["result"] = map[string]any{}
	}
	if err != nil {
		msg := err.Error()
		if len(msg) > 500 {
			msg = msg[:500]
		}
		body["status"] = "failed"
		body["error"] = msg
	}
	return c.post(ctx, ackPath, creds, body, nil)
}
