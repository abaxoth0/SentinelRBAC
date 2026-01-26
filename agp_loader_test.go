package rbac

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadActionGatePolicyFromFile(t *testing.T) {
	user := NewEntity("user")
	deleteAction, _ := user.NewAction("delete", DeletePermission)
	cache := NewResource("cache")
	adminRole := NewRole("admin", DeletePermission)

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "agp.json")

	payload := `{
		"action-gate-policy": [
			{
				"for": ["user"],
				"having": ["admin"],
				"apply": "deny",
				"doing": ["delete"],
				"on": "cache"
			}
		]
	}`

	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	policy, err := LoadActionGatePolicyFromFile(path, []Entity{user}, []Role{adminRole}, []Resource{*cache})
	if err != nil {
		t.Fatalf("expected policy to load: %v", err)
	}

	ctx := NewAuthorizationContext(&user, deleteAction, cache)
	err = Authorize(&ctx, []Role{adminRole}, &policy)
	if err != ErrActionDeniedByAGP {
		t.Fatalf("expected rule to deny action, got %v", err)
	}
}

