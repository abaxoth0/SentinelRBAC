package rbac

type Action struct {
	Name                string
	RequiredPermissions []Permission
}

// Checks if the user with the given role has enough permissions to perform the given operation.
// If the user has enough permissions, it returns nil, otherwise it returns an error.
//
// This method must be called after setting rbac.CurrentService, otherwise it will panic.
func (operation Action) Permit(userRoleName string) *Error {
	if CurrentService == nil {
		panic("CurrentService is not set")
	}

	userRole, err := CurrentService.ParseRole(userRoleName)

	if err != nil {
		return err
	}

	return Authorize(ParsePermissions(operation.RequiredPermissions), (ParsePermissions(userRole.Permissions)))
}
