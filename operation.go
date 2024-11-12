package rbac

type OperationName string

type Operation struct {
	// Unique name of operation.
	Operation OperationName

	// Array of permissions which allows to perform this operation.
	// If user has any of these permissions, he can perform this operation. (It's 'OR' not 'AND')
	RequiredPermission []PermissionTag
}

// Verifies if a user with a given role can perform an operation on a target with a specified role.
// It checks both user and target roles against the required permissions for the operation defined in the authorizationRules.
// Returns an ExternalError if the user lacks the necessary permissions or attempts forbidden operations, such as
// modifying an admin or performing moderator-to-moderator actions. Returns nil if authorization is successful.
func (operation Operation) Authorize(userRoleName string, targetRoleName string) error {
	userRole, err := ParseRole(userRoleName)

	if err != nil {
		return err
	}

	userPermissions, requiredPermissions := GetPermissions(operation.RequiredPermission, userRole)

	// All operations which has targetRoleName == role.NoneRole, but need authorization requires admin rights.
	// (For example: drop all soft deleted users)
	if targetRoleName == NoneRole && !userPermissions.Admin {
		return InsufficientPermission
	}

	targetRole, err := ParseRole(targetRoleName)

	if err != nil {
		return err
	}

	return VerifyPermissions(requiredPermissions, userPermissions, targetRole)
}
