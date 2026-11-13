// Package silo is a small client for Silo's admin user API (/api/v2), the part
// of Silo the plugin host does not expose to plugins.
//
// Silo rules this client enforces:
//   - Every write sends the user's current ETag (If-Match); a stale ETag is 412.
//   - library_ids null inherits the access group (all libraries); [] means no
//     libraries. Memberra's "all libraries" (an empty list) maps to null.
//   - POST /admin/users rejects unknown fields, including "enabled".
//   - Admin and owner accounts are never changed.
package silo

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const api = "/api/v2"

// User is the subset of a Silo account Memberra reads.
type User struct {
	ID                         string    `json:"id"`
	Username                   string    `json:"username"`
	Email                      *string   `json:"email,omitempty"`
	Enabled                    *bool     `json:"enabled,omitempty"`
	Role                       string    `json:"role,omitempty"`
	IsOwner                    bool      `json:"is_owner,omitempty"`
	LibraryIDs                 *[]string `json:"library_ids"`
	MaxStreams                 *int      `json:"max_streams,omitempty"`
	TranscodeAllowed           *bool     `json:"transcode_allowed,omitempty"`
	DownloadAllowed            *bool     `json:"download_allowed,omitempty"`
	MaxRemoteStreamBitrateKbps *int      `json:"max_remote_stream_bitrate_kbps,omitempty"`
}

// IsAdmin reports whether the account must never be managed as a customer.
func (u User) IsAdmin() bool { return u.IsOwner || u.Role == "admin" }

// Library is one Silo library.
type Library struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind,omitempty"`
}

// Error is a non-2xx Silo response.
type Error struct {
	Status int
	Action string
	Body   string
}

func (e *Error) Error() string {
	return fmt.Sprintf("silo %s failed (HTTP %d): %s", e.Action, e.Status, e.Body)
}

// ErrAdmin is returned when asked to change an admin or owner account.
var ErrAdmin = errors.New("silo account is an admin; refusing to manage it as a customer")

// ErrNotFound is returned for a user that does not exist.
var ErrNotFound = errors.New("silo user not found")

// Client talks to one Silo server with an admin API key.
type Client struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client
}

// New returns a client with sensible timeouts.
func New(baseURL, apiKey string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		APIKey:  apiKey,
		HTTP:    &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *Client) do(ctx context.Context, method, path string, body any, headers map[string]string) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return c.HTTP.Do(req)
}

func failure(res *http.Response, action string) error {
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 300))
	return &Error{Status: res.StatusCode, Action: action, Body: strings.TrimSpace(string(raw))}
}

func decode(res *http.Response, out any) error {
	defer res.Body.Close()
	return json.NewDecoder(io.LimitReader(res.Body, 8<<20)).Decode(out)
}

// Test checks that the key belongs to a Silo admin.
func (c *Client) Test(ctx context.Context) error {
	res, err := c.do(ctx, http.MethodGet, api+"/admin/users?limit=1", nil, nil)
	if err != nil {
		return fmt.Errorf("could not reach Silo at %s: %w", c.BaseURL, err)
	}
	defer res.Body.Close()
	switch {
	case res.StatusCode == http.StatusUnauthorized:
		return errors.New("Silo rejected the API key")
	case res.StatusCode == http.StatusForbidden:
		return errors.New("the API key works but isn't an admin's key; create it while signed in as a Silo admin")
	case res.StatusCode >= 300:
		return failure(res, "test connection")
	}
	var page struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.NewDecoder(res.Body).Decode(&page); err != nil || page.Items == nil {
		return errors.New("the Silo URL answered, but not like a Silo server")
	}
	return nil
}

// ListUsers returns every account, following pagination.
func (c *Client) ListUsers(ctx context.Context) ([]User, error) {
	var out []User
	cursor := ""
	for page := 0; page < 100; page++ {
		q := url.Values{"limit": {"200"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		res, err := c.do(ctx, http.MethodGet, api+"/admin/users?"+q.Encode(), nil, nil)
		if err != nil {
			return nil, err
		}
		if res.StatusCode >= 300 {
			defer res.Body.Close()
			return nil, failure(res, "list users")
		}
		var body struct {
			Items []User `json:"items"`
			Page  struct {
				HasMore    bool   `json:"has_more"`
				NextCursor string `json:"next_cursor"`
			} `json:"page"`
		}
		if err := decode(res, &body); err != nil {
			return nil, err
		}
		out = append(out, body.Items...)
		if !body.Page.HasMore || body.Page.NextCursor == "" {
			break
		}
		cursor = body.Page.NextCursor
	}
	return out, nil
}

func (c *Client) getWithETag(ctx context.Context, id string) (*User, string, error) {
	res, err := c.do(ctx, http.MethodGet, api+"/admin/users/"+url.PathEscape(id), nil, nil)
	if err != nil {
		return nil, "", err
	}
	if res.StatusCode == http.StatusNotFound {
		res.Body.Close()
		return nil, "", ErrNotFound
	}
	if res.StatusCode >= 300 {
		defer res.Body.Close()
		return nil, "", failure(res, "get user")
	}
	etag := res.Header.Get("ETag")
	var u User
	if err := decode(res, &u); err != nil {
		return nil, "", err
	}
	if etag == "" {
		return nil, "", errors.New("silo returned no ETag for the user; cannot update safely")
	}
	return &u, etag, nil
}

// GetUser returns one account.
func (c *Client) GetUser(ctx context.Context, id string) (*User, error) {
	u, _, err := c.getWithETag(ctx, id)
	return u, err
}

// Update applies a partial update to a customer account.
func (c *Client) Update(ctx context.Context, id string, patch map[string]any) (*User, error) {
	current, etag, err := c.getWithETag(ctx, id)
	if err != nil {
		return nil, err
	}
	if current.IsAdmin() {
		return nil, ErrAdmin
	}
	res, err := c.do(ctx, http.MethodPut, api+"/admin/users/"+url.PathEscape(id), patch, map[string]string{"If-Match": etag})
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= 300 {
		defer res.Body.Close()
		return nil, failure(res, "update user")
	}
	res.Body.Close()
	return c.GetUser(ctx, id)
}

// RevokeSessions ends every open sign-in of the account. Silo already rejects
// a disabled account's sessions and ends them on a password change, so this is
// extra insurance: a key whose scopes don't cover the route (403) is not an error.
func (c *Client) RevokeSessions(ctx context.Context, id string) error {
	res, err := c.do(ctx, http.MethodDelete, api+"/admin/users/"+url.PathEscape(id)+"/login-sessions", nil, nil)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 && res.StatusCode != http.StatusNotFound && res.StatusCode != http.StatusForbidden {
		return failure(res, "revoke sessions")
	}
	return nil
}

// SetEnabled enables or suspends an account. Suspending also signs it out.
func (c *Client) SetEnabled(ctx context.Context, id string, enabled bool) (*User, error) {
	u, err := c.Update(ctx, id, map[string]any{"enabled": enabled})
	if err != nil {
		return nil, err
	}
	if !enabled {
		if err := c.RevokeSessions(ctx, id); err != nil {
			return nil, err
		}
	}
	return u, nil
}

// SetLibraries scopes an account. An empty list means all libraries.
func (c *Client) SetLibraries(ctx context.Context, id string, libraries []string) (*User, error) {
	return c.Update(ctx, id, map[string]any{"library_ids": LibraryValue(libraries)})
}

// ResetPassword sets a new password and signs the account out everywhere.
func (c *Client) ResetPassword(ctx context.Context, id, password string) error {
	if _, err := c.Update(ctx, id, map[string]any{"password": password}); err != nil {
		return err
	}
	return c.RevokeSessions(ctx, id)
}

// Rename changes the account's username.
func (c *Client) Rename(ctx context.Context, id, username string) (*User, error) {
	return c.Update(ctx, id, map[string]any{"username": username})
}

// Delete removes a customer account. Deleting a missing account succeeds.
func (c *Client) Delete(ctx context.Context, id string) error {
	current, etag, err := c.getWithETag(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if current.IsAdmin() {
		return ErrAdmin
	}
	res, err := c.do(ctx, http.MethodDelete, api+"/admin/users/"+url.PathEscape(id), nil, map[string]string{"If-Match": etag})
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 && res.StatusCode != http.StatusNotFound {
		return failure(res, "delete user")
	}
	return nil
}

var unsafeEmail = regexp.MustCompile(`[^a-z0-9._-]`)

// Create makes a customer account. Without a password a random one is set:
// customers set their own through Memberra.
func (c *Client) Create(ctx context.Context, username, password string, libraries []string) (*User, error) {
	if password == "" {
		buf := make([]byte, 24)
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		password = hex.EncodeToString(buf)
	}
	body := map[string]any{
		"username": username,
		// Silo requires an email; customers sign in with their username.
		"email":                  unsafeEmail.ReplaceAllString(strings.ToLower(username), "") + "@users.memberra.invalid",
		"password":               password,
		"role":                   "user",
		"create_default_profile": true,
		"library_ids":            LibraryValue(libraries),
	}
	res, err := c.do(ctx, http.MethodPost, api+"/admin/users", body, nil)
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= 300 {
		defer res.Body.Close()
		return nil, failure(res, "create user")
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := decode(res, &created); err != nil {
		return nil, err
	}
	if created.ID == "" {
		return nil, errors.New("silo returned no user id")
	}
	return c.GetUser(ctx, created.ID)
}

// FindByUsername returns the account with this username (case-insensitive).
func (c *Client) FindByUsername(ctx context.Context, username string) (*User, error) {
	users, err := c.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	for i := range users {
		if strings.EqualFold(users[i].Username, username) {
			return &users[i], nil
		}
	}
	return nil, nil
}

// ListLibraries returns every library on the server. It reads the libraries
// visible to the key's (admin) account, which a key scoped to libraries:read
// may read; the admin-only /libraries route is the fallback for older servers.
func (c *Client) ListLibraries(ctx context.Context) ([]Library, error) {
	res, err := c.do(ctx, http.MethodGet, api+"/user/libraries", nil, nil)
	if err != nil {
		return nil, err
	}
	if res.StatusCode == http.StatusNotFound {
		res.Body.Close()
		if res, err = c.do(ctx, http.MethodGet, api+"/libraries", nil, nil); err != nil {
			return nil, err
		}
	}
	if res.StatusCode >= 300 {
		defer res.Body.Close()
		return nil, failure(res, "list libraries")
	}
	var raw json.RawMessage
	if err := decode(res, &raw); err != nil {
		return nil, err
	}
	var rows []map[string]any
	if json.Unmarshal(raw, &rows) != nil {
		var wrapped struct {
			Items []map[string]any `json:"items"`
		}
		if err := json.Unmarshal(raw, &wrapped); err != nil {
			return nil, err
		}
		rows = wrapped.Items
	}
	out := make([]Library, 0, len(rows))
	for _, row := range rows {
		lib := Library{ID: fmt.Sprint(row["id"]), Name: fmt.Sprint(row["name"])}
		if k, ok := row["kind"].(string); ok {
			lib.Kind = k
		} else if k, ok := row["type"].(string); ok {
			lib.Kind = k
		}
		if lib.ID != "" && lib.ID != "<nil>" {
			out = append(out, lib)
		}
	}
	return out, nil
}

// LibraryValue maps Memberra's library list to Silo's: empty means all (null).
func LibraryValue(libraries []string) any {
	if len(libraries) == 0 {
		return nil
	}
	return libraries
}
