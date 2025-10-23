package rbac

type AuthzFunc func(Permissions, Permissions) *Error

var authorize AuthzFunc = AuthorizeCRUDFunc

// AuthorizationFunc checks user's permissions.
//
// This function is encapsulated in rbac package, so it can't be called directly,
// instead use "Authorize" function.
//
// AuthorizationFunc can be overridden via this function, to implement custom authorization logic.
// By default it uses the AuthorizeCRUDFunc function.
func SetAuthzFunc(fn AuthzFunc) {
	if fn == nil {
		panic("authorization function can't be nil")
	}

	authorize = fn
}

// Checks if the "permitted" permissions are sufficient to satisfy the "required" CRUD permissions.
//
// It returns an "InsufficientPermissions" error if any of the "required" permissions are not covered by the "permitted" permissions.
func AuthorizeCRUDFunc(required Permissions, permitted Permissions) *Error {
	// To verify that 'permitted' satisfies 'required' need to check
	// if all 1 bits in 'required' are set in 'permitted',
	// For that need to perform a bitwise AND between 'required' and 'permitted',
	// then verify if the result equals 'required'.
	// If (required & permitted) == required, all ones in required are present in permitted.
	if required&permitted != required {
		return InsufficientPermissions
	}

	return nil
}

// Checks if the user has sufficient permissions to perform an action on this resource.
//
// Returns an error if any of the required permissions for the action are not covered by given roles.
func Authorize(ctx *AuthorizationContext, roles []Role, AGP *ActionGatePolicy) *Error {
	if !ctx.Entity.HasAction(ctx.Action) {
		return EntityDoesNotHaveSuchAction
	}

	if AGP != nil {
		if rule, ok := AGP.GetRule(ctx); ok {
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

	if err := authorize(requiredPermissions, mergredPermissions); err == nil {
		return nil
	}

	return InsufficientPermissions
}
