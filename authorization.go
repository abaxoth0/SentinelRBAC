package rbac

type AuthFunc func(*PermissionsTable, *PermissionsTable) *Error

// Checks if the "permitted" permissions are sufficient to satisfy the "required" permissions.
//
// Can be redefined. In default implementation:
//
// It returns nil if all "required" permissions are covered by the "permitted" permissions; otherwise,
// it returns an "InsufficientPermissions" error.
// Admins and moderators have full CRUD capabilities regardless of specific permissions.
var Authorize AuthFunc = func(required *PermissionsTable, permitted *PermissionsTable) *Error {
	if required.Admin && !permitted.Admin {
		return InsufficientPermissions
	}

	if required.Moderator && (!permitted.Moderator || !permitted.Admin) {
		return InsufficientPermissions
	}

	if permitted.Admin || permitted.Moderator {
		return nil
	}

	return AuthorizeCRUD(required, permitted)
}

// Checks if the "permitted" permissions are sufficient to satisfy the "required" CRUD (create, read, update, delete) permissions.
//
// It returns an InsufficientPermissions error if any of the "required" permissions are not covered by the "permitted" permissions.
//
// It doesn't check for admin or moderator permissions (as they are covered by "Authorize").
func AuthorizeCRUD(required *PermissionsTable, permitted *PermissionsTable) *Error {
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
