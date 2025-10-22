package rbac

import (
	"testing"
)

func TestActionGatePolicy(t *testing.T) {
	user := NewEntity("user")
	readAction, _ := user.NewAction("read", ReadPermission)
	cache := NewResource("cache")
	adminRole := NewRole("admin", ReadPermission)

	// Test effect validation
	if err := DenyActionGateEffect.Validate(); err != nil {
		t.Errorf("Valid effect should not error: %v", err)
	}

	invalidEffect := ActionGateEffect("invalid")
	if err := invalidEffect.Validate(); err == nil {
		t.Error("Invalid effect should error")
	}

	// Test rule creation and validation
	ctx := NewAuthorizationContext(&user, readAction, cache)
	rule := NewActionGateRule(&ctx, DenyActionGateEffect, []Role{adminRole})

	if err := rule.Validate(); err != nil {
		t.Errorf("Valid rule should not error: %v", err)
	}

	// Test rule application
	bypass, err := rule.Apply(readAction, []Role{adminRole})
	if err != ActionDeniedByAGP {
		t.Errorf("Expected ActionDeniedByAGP, got %v", err)
	}
	if bypass {
		t.Error("Deny rule should not bypass")
	}

	// Test policy management
	agp := NewActionGatePolicy()

	if err := agp.AddRule(rule); err != nil {
		t.Errorf("Failed to add rule: %v", err)
	}

	retrievedRule, exists := agp.GetRule(&ctx)
	if !exists {
		t.Error("Rule should exist in policy")
	}
	if retrievedRule != rule {
		t.Error("Retrieved rule should be the same")
	}

	// Test duplicate rule
	if err := agp.AddRule(rule); err == nil {
		t.Error("Duplicate rule should error")
	}
}
