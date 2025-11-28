package rbac

// AuthzFunc checks user's permissions.
type AuthzFunc func(Permissions, Permissions) error

// RuleProvider can lookup ActionGate rules for provided context.
type RuleProvider interface {
	GetRule(ctx *AuthorizationContext) (*ActionGateRule, bool)
}

// Authorizer encapsulates authorization behavior.
type Authorizer struct {
	authzFunc AuthzFunc
}

// NewAuthorizer creates authorizer with default authorization function.
func NewAuthorizer() *Authorizer {
	return &Authorizer{
		authzFunc: AuthorizeCRUDFunc,
	}
}

var defaultAuthorizer = NewAuthorizer()

// SetAuthzFunc overrides default authorization function globally.
func SetAuthzFunc(fn AuthzFunc) {
	defaultAuthorizer.SetAuthzFunc(fn)
}

// SetAuthzFunc overrides authorization function for this authorizer.
func (a *Authorizer) SetAuthzFunc(fn AuthzFunc) {
	if fn == nil {
		panic("authorization function can't be nil")
	}
	a.authzFunc = fn
}

// Checks if the "permitted" permissions are sufficient to satisfy the "required" CRUD permissions.
//
// It returns an "InsufficientPermissions" error if any of the "required" permissions are not covered by the "permitted" permissions.
func AuthorizeCRUDFunc(required Permissions, permitted Permissions) error {
	// To verify that 'permitted' satisfies 'required' need to check
	// if all 1 bits in 'required' are set in 'permitted',
	// For that need to perform a bitwise AND between 'required' and 'permitted',
	// then verify if the result equals 'required'.
	// If (required & permitted) == required, all ones in required are present in permitted.
	if required&permitted != required {
		return ErrInsufficientPermissions
	}

	return nil
}

// Checks if the user has sufficient permissions to perform an action on this resource.
//
// Returns an error if any of the required permissions for the action are not covered by given roles.
func Authorize(ctx *AuthorizationContext, roles []Role, provider RuleProvider) error {
	return defaultAuthorizer.Authorize(ctx, roles, provider)
}

// Authorize checks authorization using provided rule provider.
func (a *Authorizer) Authorize(ctx *AuthorizationContext, roles []Role, provider RuleProvider) error {
	if !ctx.Entity.HasAction(ctx.Action) {
		return ErrEntityDoesNotHaveSuchAction
	}

	if provider != nil {
		if rule, ok := provider.GetRule(ctx); ok {
			bypass, err := rule.Apply(ctx.Action, roles)
			if err != nil {
				return err
			}
			if bypass {
				return nil
			}
		}
	}

	requiredPermissions := ctx.Entity.actions[ctx.Action]
	mergredPermissions := Permissions(0)

	for _, role := range roles {
		mergredPermissions |= role.Permissions
	}

	if err := a.authzFunc(requiredPermissions, mergredPermissions); err != nil {
		return err
	}

	return nil
}
