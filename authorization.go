package rbac

import "errors"

type AuthorizationFunc func(*Permissions, *Permissions) *Error

var auth AuthorizationFunc = AuthorizeCRUD

// AuthorizationFunc checks user's permissions.
//
// This function is incapsulated in rbac package, so it can't be called directly,
// instead use "Authorize" function.
//
// AuthorizationFunc can be overridden via this function, to implement custom authorization logic.
// By default it uses the AuthorizeCRUD function.
func SetAuthorizationFunc(fn AuthorizationFunc) {
	if fn == nil {
		panic("authorization function can't be nil")
	}

	auth = fn
}

// Checks if the "permitted" permissions are sufficient to satisfy the "required" CRUD permissions.
//
// It returns an "InsufficientPermissions" error if any of the "required" permissions are not covered by the "permitted" permissions.
func AuthorizeCRUD(required *Permissions, permitted *Permissions) *Error {
	if required.Create && (!permitted.Create) {
		return InsufficientPermissions
	}

	if required.SelfCreate && (!permitted.Create || !permitted.SelfCreate) {
		return InsufficientPermissions
	}

	if required.Create && (!permitted.Create) {
		return InsufficientPermissions
	}

	if required.SelfRead && (!permitted.Read || !permitted.SelfRead) {
		return InsufficientPermissions
	}

	if required.Update && (!permitted.Update) {
		return InsufficientPermissions
	}

	if required.SelfUpdate && (!permitted.Update || !permitted.SelfUpdate) {
		return InsufficientPermissions
	}

	if required.Delete && (!permitted.Delete) {
		return InsufficientPermissions
	}

	if required.SelfDelete && (!permitted.Delete || !permitted.SelfDelete) {
		return InsufficientPermissions
	}

	return nil
}

// Authorize checks if the user has sufficient permissions to perform an action on a resource.
//
// It takes an Action, a Resource, and a list of user's roles.
// It returns an error if any of the required permissions for the action are not covered by the user's roles.
// If the user has sufficient permissions, it returns nil.
func Authorize(act Action, resource *Resource, rolesNames []string) error {
	requiredPermissions := actions[act]

	if requiredPermissions == nil {
		return errors.New("action \"" + act.String() + "\" wasn't found")
	}

	permitted := false

	for _, roleName := range rolesNames {
		permissions := resource.Permissions[roleName]

		if permissions == nil {
			return NewError("permissions of resource \"" + resource.Name + "\" for \"" + roleName + "\" role is not defined")
		}

		if err := auth(requiredPermissions, permissions); err == nil {
			permitted = true
			break
		}
	}

	if !permitted {
		return InsufficientPermissions
	}

	return nil
}
