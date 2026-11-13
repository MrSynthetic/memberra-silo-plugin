// Package bridge turns Memberra commands into Silo admin API calls and keeps
// the plugin's connection to Memberra alive.
package bridge

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/MrSynthetic/memberra/plugins/silo/internal/memberra"
	"github.com/MrSynthetic/memberra/plugins/silo/internal/silo"
)

// Capabilities advertised to Memberra. Memberra only sends a command type when
// the matching capability is true.
var Capabilities = map[string]bool{
	"plugin_provisioning": true,
	"suspend_user":        true,
	"rename_user":         true,
	"password_reset":      true,
	"user_inventory":      true,
	"apply_entitlements":  true,
}

var safeName = regexp.MustCompile(`^[A-Za-z0-9._@ -]{1,64}$`)

// entitlementFields are the only account fields a package may change.
var entitlementFields = map[string]bool{
	"max_streams":                    true,
	"transcode_allowed":              true,
	"download_allowed":               true,
	"max_remote_stream_bitrate_kbps": true,
}

func str(p map[string]any, key string) string {
	v, _ := p[key].(string)
	return strings.TrimSpace(v)
}

func required(p map[string]any, key string) (string, error) {
	v := str(p, key)
	if v == "" {
		return "", fmt.Errorf("missing %s", key)
	}
	return v, nil
}

// libraries reads an optional list of library ids. ok is false when absent.
func libraries(p map[string]any) (ids []string, ok bool, err error) {
	raw, present := p["libraries"]
	if !present || raw == nil {
		return nil, false, nil
	}
	list, isList := raw.([]any)
	if !isList {
		return nil, false, errors.New("libraries must be a list")
	}
	if len(list) > 128 {
		return nil, false, errors.New("too many libraries")
	}
	ids = make([]string, 0, len(list))
	for _, item := range list {
		id := strings.TrimSpace(fmt.Sprint(item))
		if id == "" || len(id) > 128 {
			return nil, false, errors.New("invalid library id")
		}
		ids = append(ids, id)
	}
	return ids, true, nil
}

func userResult(u *silo.User) map[string]any {
	return map[string]any{"providerUserId": u.ID, "providerUsername": u.Username}
}

// Execute runs one command. The result is returned to Memberra and must not
// contain secrets.
func Execute(ctx context.Context, s *silo.Client, cmd memberra.Command) (map[string]any, error) {
	p := cmd.Payload
	if p == nil {
		p = map[string]any{}
	}
	switch cmd.Type {
	case "provision_user":
		username, err := required(p, "username")
		if err != nil {
			return nil, err
		}
		if !safeName.MatchString(username) {
			return nil, errors.New("invalid username")
		}
		libs, _, err := libraries(p)
		if err != nil {
			return nil, err
		}
		// Idempotent: a retried command finds the account it already created.
		existing, err := s.FindByUsername(ctx, username)
		if err != nil {
			return nil, err
		}
		if existing != nil {
			if existing.IsAdmin() {
				return nil, silo.ErrAdmin
			}
			if _, err := s.Update(ctx, existing.ID, map[string]any{"enabled": true, "library_ids": silo.LibraryValue(libs)}); err != nil {
				return nil, err
			}
			return userResult(existing), nil
		}
		u, err := s.Create(ctx, username, str(p, "password"), libs)
		if err != nil {
			return nil, err
		}
		return userResult(u), nil

	case "restore_user":
		id, err := required(p, "userId")
		if err != nil {
			return nil, err
		}
		patch := map[string]any{"enabled": true}
		if libs, ok, err := libraries(p); err != nil {
			return nil, err
		} else if ok {
			patch["library_ids"] = silo.LibraryValue(libs)
		}
		u, err := s.Update(ctx, id, patch)
		if err != nil {
			return nil, err
		}
		return userResult(u), nil

	case "suspend_user":
		id, err := required(p, "userId")
		if err != nil {
			return nil, err
		}
		if _, err := s.SetEnabled(ctx, id, false); err != nil {
			return nil, err
		}
		return map[string]any{"providerUserId": id, "suspended": true}, nil

	case "update_libraries":
		id, err := required(p, "userId")
		if err != nil {
			return nil, err
		}
		libs, ok, err := libraries(p)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errors.New("missing libraries")
		}
		if _, err := s.SetLibraries(ctx, id, libs); err != nil {
			return nil, err
		}
		return map[string]any{"providerUserId": id}, nil

	case "rename_user":
		id, err := required(p, "userId")
		if err != nil {
			return nil, err
		}
		name, err := required(p, "username")
		if err != nil {
			return nil, err
		}
		if !safeName.MatchString(name) {
			return nil, errors.New("invalid username")
		}
		u, err := s.Rename(ctx, id, name)
		if err != nil {
			return nil, err
		}
		return userResult(u), nil

	case "reset_password":
		id, err := required(p, "userId")
		if err != nil {
			return nil, err
		}
		pw, _ := p["password"].(string)
		if len(pw) < 8 || len(pw) > 128 {
			return nil, errors.New("password must be 8 to 128 characters")
		}
		if err := s.ResetPassword(ctx, id, pw); err != nil {
			return nil, err
		}
		return map[string]any{"providerUserId": id}, nil

	case "delete_user":
		id, err := required(p, "userId")
		if err != nil {
			return nil, err
		}
		if err := s.Delete(ctx, id); err != nil {
			return nil, err
		}
		return map[string]any{"providerUserId": id, "deleted": true}, nil

	case "apply_entitlements":
		id, err := required(p, "userId")
		if err != nil {
			return nil, err
		}
		raw, _ := p["patch"].(map[string]any)
		patch := map[string]any{}
		for k, v := range raw {
			if !entitlementFields[k] {
				return nil, fmt.Errorf("field %q is not a package limit", k)
			}
			if f, isNum := v.(float64); isNum {
				v = int(f)
			}
			patch[k] = v
		}
		if len(patch) == 0 {
			return nil, errors.New("no package limits to apply")
		}
		if _, err := s.Update(ctx, id, patch); err != nil {
			return nil, err
		}
		return map[string]any{"providerUserId": id, "applied": len(patch)}, nil

	case "list_users":
		users, err := s.ListUsers(ctx)
		if err != nil {
			return nil, err
		}
		rows := make([]map[string]any, 0, len(users))
		for _, u := range users {
			row := map[string]any{
				"id":              u.ID,
				"username":        u.Username,
				"email":           nil,
				"isAdministrator": u.IsAdmin(),
			}
			if u.Enabled != nil {
				row["enabled"] = *u.Enabled
			}
			rows = append(rows, row)
		}
		return map[string]any{"users": rows}, nil
	}
	return nil, fmt.Errorf("unsupported command %q", cmd.Type)
}
