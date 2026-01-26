package rbac

import (
	"errors"
)

type Action string

func (a Action) String() string {
	return string(a)
}

type ActionGateEffect string

func (e ActionGateEffect) Validate() error {
	if ok := agEffectMap[e]; !ok {
		return errors.New("Action Gate Effect \"" + string(e) + "\" doesn't exist")
	}
	return nil
}

const (
	// Deny action, even if it should be successfully authorized
	DenyActionGateEffect ActionGateEffect = "deny"
	// Require specific role for action. Without it all actions will be denied
	RequireActionGateEffect ActionGateEffect = "require"
	// Immediately authorize an action regardless of roles.
	AllowActionGateEffect ActionGateEffect = "allow"
)

// Used for validating AG effects
var agEffectMap = map[ActionGateEffect]bool{
	DenyActionGateEffect:    true,
	RequireActionGateEffect: true,
	AllowActionGateEffect:   true,
}

// Required fields are: Entity, Effect, Actions and Resource.
// Actions can contain one or more actions that this rule applies to.
type ActionGateRule struct {
	Entity   Entity
	Effect   ActionGateEffect
	Roles    []Role
	Actions  []Action // Multiple actions this rule applies to
	Resource Resource
}

// NewActionGateRule creates a new ActionGateRule for a single action.
func NewActionGateRule(ctx *AuthorizationContext, effect ActionGateEffect, roles []Role) *ActionGateRule {
	return &ActionGateRule{
		Entity:   *ctx.Entity,
		Effect:   effect,
		Roles:    roles,
		Actions:  []Action{ctx.Action},
		Resource: *ctx.Resource,
	}
}

// NewActionGateRuleForActions creates a new ActionGateRule for multiple actions.
func NewActionGateRuleForActions(entity *Entity, actions []Action, resource *Resource, effect ActionGateEffect, roles []Role) *ActionGateRule {
	return &ActionGateRule{
		Entity:   *entity,
		Effect:   effect,
		Roles:    roles,
		Actions:  actions,
		Resource: *resource,
	}
}

// Validates that required fields are non-zero.
func (r *ActionGateRule) Validate() error {
	if err := r.Effect.Validate(); err != nil {
		return errors.New("invalid action gate rule: " + err.Error())
	}
	if r.Roles == nil || len(r.Roles) == 0 {
		return errors.New("invalid action gate rule: roles are missing")
	}
	if r.Entity.name == "" {
		return errors.New("invalid action gate rule: entity name is missing")
	}
	if r.Actions == nil || len(r.Actions) == 0 {
		return errors.New("invalid action gate rule: actions are missing")
	}
	var zeroResource Resource
	if r.Resource == zeroResource {
		return errors.New("invalid action gate rule: resource is missing")
	}
	return nil
}

// Applies this rule for the given action with roles.
// Returns true if default authorization must be skipped.
func (r *ActionGateRule) Apply(act Action, roles []Role) (bypassAuthz bool, err error) {
	// Check if this rule applies to the given action
	actionMatches := false
	for _, ruleAction := range r.Actions {
		if ruleAction == act {
			actionMatches = true
			break
		}
	}
	if !actionMatches {
		return false, nil
	}

	matchRuleRoles := false

	for _, ruleRole := range r.Roles {
		for _, role := range roles {
			if role.Name == ruleRole.Name {
				matchRuleRoles = true
				break
			}
		}
	}

	switch r.Effect {
	case DenyActionGateEffect:
		if matchRuleRoles {
			return false, ErrActionDeniedByAGP
		}
	case RequireActionGateEffect:
		if !matchRuleRoles {
			return false, ErrActionDeniedByAGP
		}
	case AllowActionGateEffect:
		if matchRuleRoles {
			return true, nil
		}
	default:
		panic("unknown action gate effect: " + r.Effect)
	}

	return false, nil
}

type ActionGatePolicy struct {
	// Two-level index for efficient lookup:
	// 1. Primary: entity:action:resource -> list of rules (O(1) to get list)
	// 2. Secondary: iterate small list to find matching rule (O(k) where k is typically 1-3)
	// This avoids rule explosion (one rule object per entity+resource+effect+roles)
	// while providing efficient lookup (O(k) where k is very small)
	index map[string][]*ActionGateRule
}

func NewActionGatePolicy() ActionGatePolicy {
	return ActionGatePolicy{
		index: map[string][]*ActionGateRule{},
	}
}

// keyFrom creates a lookup key for entity:action:resource (without effect/roles).
// This allows us to quickly find all rules for a given entity+action+resource combination.
func (agp ActionGatePolicy) keyFrom(entity *Entity, action Action, resource *Resource) string {
	return entity.name + ":" + action.String() + ":" + resource.name
}

// GetRule finds a rule that matches the given context.
// Uses two-level indexing: O(1) to get rule list, then O(k) to find match where k is small.
// Returns the first matching rule (typically there's only one rule per entity+action+resource).
func (agp ActionGatePolicy) GetRule(ctx *AuthorizationContext) (*ActionGateRule, bool) {
	// Get all rules for this entity+action+resource combination (O(1) lookup)
	lookupKey := agp.keyFrom(ctx.Entity, ctx.Action, ctx.Resource)
	rules, exists := agp.index[lookupKey]
	if !exists || len(rules) == 0 {
		return nil, false
	}

	// Iterate through rules to find one that matches this action (O(k) where k is typically 1-3)
	for _, rule := range rules {
		// Check if this rule applies to the requested action
		for _, ruleAction := range rule.Actions {
			if ruleAction == ctx.Action {
				return rule, true
			}
		}
	}

	return nil, false
}

// Adds new rule in policy. Creates index entries for each action in the rule,
// all pointing to the same rule object (shared reference, no duplication).
// This avoids rule explosion while maintaining efficient lookup.
func (agp ActionGatePolicy) AddRule(rule *ActionGateRule) error {
	if err := rule.Validate(); err != nil {
		return err
	}

	// For each action in the rule, add the rule to the index
	// Multiple actions point to the same rule object (no duplication)
	for _, action := range rule.Actions {
		key := agp.keyFrom(&rule.Entity, action, &rule.Resource)

		// Check if a rule already exists for this entity+action+resource
		existingRules := agp.index[key]

		// Check for duplicate rule (same entity, resource, effect, and roles)
		for _, existing := range existingRules {
			if existing.Entity.name == rule.Entity.name &&
				existing.Resource.name == rule.Resource.name &&
				existing.Effect == rule.Effect &&
				rolesEqual(existing.Roles, rule.Roles) {
				return errors.New("rule already exists in action gate policy")
			}
		}

		// Add rule to the list (shared reference, no duplication)
		agp.index[key] = append(existingRules, rule)
	}

	return nil
}

// rolesEqual checks if two role slices contain the same roles (order-independent).
func rolesEqual(a, b []Role) bool {
	if len(a) != len(b) {
		return false
	}

	// Create a map for quick lookup
	bMap := make(map[string]bool, len(b))
	for _, role := range b {
		bMap[role.Name] = true
	}

	// Check if all roles in a exist in b
	for _, role := range a {
		if !bMap[role.Name] {
			return false
		}
	}

	return true
}
