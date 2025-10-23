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

// Required fields are: Entity, Effect, Action and Resource.
type ActionGateRule struct {
	Entity   Entity
	Effect   ActionGateEffect
	Roles    []Role
	Action   Action
	Resource Resource
}

func NewActionGateRule(ctx *AuthorizationContext, effect ActionGateEffect, roles []Role) *ActionGateRule {
	return &ActionGateRule{
		Entity:   *ctx.Entity,
		Effect:   effect,
		Roles:    roles,
		Action:   ctx.Action,
		Resource: *ctx.Resource,
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
	if r.Action == "" {
		return errors.New("invalid action gate rule: action is missing")
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
	if r.Roles != nil && r.Action != act {
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
	rules map[string]*ActionGateRule
}

func NewActionGatePolicy() ActionGatePolicy {
	return ActionGatePolicy{
		rules: map[string]*ActionGateRule{},
	}
}

func (agp ActionGatePolicy) keyFrom(entity *Entity, act Action, resource *Resource) string {
	return entity.name + ":" + act.String() + ":" + resource.name
}

func (agp ActionGatePolicy) GetRule(ctx *AuthorizationContext) (*ActionGateRule, bool) {
	rule, ok := agp.rules[agp.keyFrom(ctx.Entity, ctx.Action, ctx.Resource)]
	return rule, ok
}

// Adds new rule in police, will return error if rule
// is either invalid, either already exist in policy
func (agp ActionGatePolicy) AddRule(rule *ActionGateRule) error {
	if err := rule.Validate(); err != nil {
		return err
	}

	key := agp.keyFrom(&rule.Entity, rule.Action, &rule.Resource)

	if _, ok := agp.rules[key]; ok {
		return errors.New("rule " + key + " already exists in action gate policy")
	}

	agp.rules[key] = rule

	return nil
}
