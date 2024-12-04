package rbac

type AuthorizationFunc func(*Permissions, *Permissions) *Error

// Function that checks user's permissions.
//
// This function is not supposed to be called directly,
// instead use method "AuthorizeAction" of an entity struct.
//
// This function can be overridden to implement custom authorization logic.
// By default it uses the AuthorizeCRUD function.
var Authorize AuthorizationFunc = AuthorizeCRUD

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
