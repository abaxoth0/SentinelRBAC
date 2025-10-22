package rbac

import (
	"testing"
)

func TestAuthorizeCRUDFunc(t *testing.T) {
	tests := []struct {
		name      string
		required  Permissions
		permitted Permissions
		expectErr bool
	}{
		{"exact match", ReadPermission, ReadPermission, false},
		{"more permissions", ReadPermission, ReadPermission | CreatePermission, false},
		{"insufficient", ReadPermission | CreatePermission, ReadPermission, true},
		{"no permissions", ReadPermission, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := AuthorizeCRUDFunc(tt.required, tt.permitted)
			if tt.expectErr && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("Expected nil, got %v", err)
			}
		})
	}
}

func TestSetAuthzFunc(t *testing.T) {
	// Test custom function
	customFunc := func(required, permitted Permissions) *Error {
		if required == 0 {
			return NewError("custom error")
		}
		return nil
	}

	SetAuthzFunc(customFunc)
	err := authorize(0, ReadPermission)
	if err == nil {
		t.Error("Expected custom error, got nil")
	}

	// Reset and test panic
	SetAuthzFunc(AuthorizeCRUDFunc)
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic when setting nil function")
		}
	}()
	SetAuthzFunc(nil)
}

func TestAuthorize(t *testing.T) {
	user := NewEntity("user")
	readAction, _ := user.NewAction("read", ReadPermission)
	writeAction, _ := user.NewAction("write", CreatePermission|UpdatePermission)
	cache := NewResource("cache")

	userRole := NewRole("user", SelfReadPermission)
	adminRole := NewRole("admin", CreatePermission|ReadPermission|UpdatePermission|DeletePermission)

	tests := []struct {
		name      string
		action    Action
		roles     []Role
		expectErr bool
	}{
		{"admin can read", readAction, []Role{adminRole}, false},
		{"user cannot write", writeAction, []Role{userRole}, true},
		{"combined roles work", writeAction, []Role{userRole, adminRole}, false},
		{"empty roles fail", readAction, []Role{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := NewAuthorizationContext(&user, tt.action, cache)
			err := Authorize(&ctx, tt.roles, nil)

			if tt.expectErr && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("Expected nil, got %v", err)
			}
		})
	}
}

func TestAuthorizeWithActionGatePolicy(t *testing.T) {
	user := NewEntity("user")
	readAction, _ := user.NewAction("read", ReadPermission)
	cache := NewResource("cache")
	adminRole := NewRole("admin", ReadPermission)
	userRole := NewRole("user", SelfReadPermission)

	agp := NewActionGatePolicy()
	ctx := NewAuthorizationContext(&user, readAction, cache)

	// Add deny rule
	rule := NewActionGateRule(&ctx, DenyActionGateEffect, []Role{adminRole})
	agp.AddRule(rule)

	// Test deny effect
	err := Authorize(&ctx, []Role{adminRole}, &agp)
	if err != ActionDeniedByAGP {
		t.Errorf("Expected ActionDeniedByAGP, got %v", err)
	}

	// Test no rule applies
	err = Authorize(&ctx, []Role{userRole}, &agp)
	if err != InsufficientPermissions {
		t.Errorf("Expected InsufficientPermissions, got %v", err)
	}
}
