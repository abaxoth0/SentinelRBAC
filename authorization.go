package rbac

type AuthFunc func(*Permissions, *Permissions) *Error

var Authorize AuthFunc = func(required *Permissions, permitted *Permissions) *Error {
	return AuthorizeCRUD(required, permitted)
}

// Checks if the "permitted" permissions are sufficient to satisfy the "required" CRUD (create, read, update, delete) permissions.
//
// It returns an InsufficientPermissions error if any of the "required" permissions are not covered by the "permitted" permissions.
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
