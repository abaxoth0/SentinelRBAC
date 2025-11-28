package rbac

import (
	"testing"
)

func TestCompleteAuthorizationFlow(t *testing.T) {
	// Setup
	user := NewEntity("user")
	readAction, _ := user.NewAction("read", ReadPermission)
	writeAction, _ := user.NewAction("write", CreatePermission|UpdatePermission)
	cache := NewResource("cache")

	guestRole := NewRole("guest", 0)
	userRole := NewRole("user", SelfReadPermission)
	adminRole := NewRole("admin", CreatePermission|ReadPermission|UpdatePermission|DeletePermission)

	tests := []struct {
		name      string
		action    Action
		roles     []Role
		expectErr bool
	}{
		{"guest cannot read", readAction, []Role{guestRole}, true},
		{"user cannot read (self vs regular)", readAction, []Role{userRole}, true},
		{"admin can read", readAction, []Role{adminRole}, false},
		{"user cannot write", writeAction, []Role{userRole}, true},
		{"admin can write", writeAction, []Role{adminRole}, false},
		{"combined roles work", writeAction, []Role{userRole, adminRole}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := NewAuthorizationContext(&user, tt.action, cache)
			err := Authorize(&ctx, tt.roles, nil)

			if tt.expectErr && err == nil {
				t.Errorf("Expected error for: %s", tt.name)
			}
			if !tt.expectErr && err != nil {
				t.Errorf("Expected no error for: %s, got %v", tt.name, err)
			}
		})
	}
}

func TestAuthorizationWithActionGatePolicy(t *testing.T) {
	user := NewEntity("user")
	readAction, _ := user.NewAction("read", ReadPermission)
	cache := NewResource("cache")
	adminRole := NewRole("admin", ReadPermission)

	agp := NewActionGatePolicy()
	ctx := NewAuthorizationContext(&user, readAction, cache)

	// Add deny rule for admin
	rule := NewActionGateRule(&ctx, DenyActionGateEffect, []Role{adminRole})
	agp.AddRule(rule)

	// Test deny effect
	err := Authorize(&ctx, []Role{adminRole}, &agp)
	if err != ErrActionDeniedByAGP {
		t.Errorf("Expected ActionDeniedByAGP, got %v", err)
	}

	// Test allow effect
	allowRule := NewActionGateRule(&ctx, AllowActionGateEffect, []Role{adminRole})
	agp2 := NewActionGatePolicy()
	agp2.AddRule(allowRule)

	err = Authorize(&ctx, []Role{adminRole}, &agp2)
	if err != nil {
		t.Errorf("Expected no error with allow rule, got %v", err)
	}
}
