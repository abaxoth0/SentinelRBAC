package rbac

type OperationName string

type Operation struct {
	// Unique name of operation.
	Name OperationName

	RequiredPermissions []PermissionTag
}

// Checks if the user has enough permissions to perform operation on user with the target role.
func (operation Operation) Authorize(userRoleName string) *Error {
	userRole, err := ParseRole(userRoleName, CurrentService)

	if err != nil {
		return err
	}

	return VerifyPermissions(GetPermissions(operation.RequiredPermissions), GetPermissions(userRole.Permissions))
}
