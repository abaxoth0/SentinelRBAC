package rbac

type ActionName string

type Action struct {
	Name                ActionName
	RequiredPermissions []PermissionTag
}

// Checks if the user has enough permissions to perform operation on user with the target role.
func (operation Action) Authorize(userRoleName string) *Error {
	userRole, err := ParseRole(userRoleName, CurrentService)

	if err != nil {
		return err
	}

	return VerifyPermissions(GetPermissions(operation.RequiredPermissions), GetPermissions(userRole.Permissions))
}
