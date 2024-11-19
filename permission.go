package rbac

import (
	"slices"
)

type permission string

func (p permission) String() string {
	return string(p)
}

const CreatePermission permission = "CREATE"
const SelfCreatePermission permission = "SELF-CREATE"

const ReadPermission permission = "READ"
const SelfReadPermission permission = "SELF-READ"

const UpdatePermission permission = "UPDATE"
const SelfUpdatePermission permission = "SELF-UPDATE"

const DeletePermission permission = "DELETE"
const SelfDeletePermission permission = "SELF-DELETE"

const ModeratorPermission permission = "MODERATOR"
const AdminPermission permission = "ADMIN"
const ServicePermission permission = "SERVICE"

var permissions [11]permission = [11]permission{
	CreatePermission,
	SelfCreatePermission,
	ReadPermission,
	SelfReadPermission,
	UpdatePermission,
	SelfUpdatePermission,
	DeletePermission,
	SelfDeletePermission,
	ModeratorPermission,
	AdminPermission,
	ServicePermission,
}

// Returns an array of all available permissions.
func Permissions() [11]permission {
	return permissions
}

type PermissionsTable struct {
	Create     bool
	SelfCreate bool
	Read       bool
	SelfRead   bool
	Update     bool
	SelfUpdate bool
	Delete     bool
	SelfDelete bool
	Admin      bool
	Moderator  bool
	Service    bool
}

var InsufficientPermissions *Error = NewError("Insufficient permissions to perform this action")

// Converts a slice of Permission into a PermissionsTable.
//
// It doesn't check if a permission is valid or not, it just sets the corresponding
// boolean field of the PermissionsTable to true if the permission is present in the
// slice.
func ParsePermissions(p []permission) *PermissionsTable {
	return &PermissionsTable{
		Service:    slices.Contains(p, ServicePermission),
		Admin:      slices.Contains(p, AdminPermission),
		Moderator:  slices.Contains(p, ModeratorPermission),
		Create:     slices.Contains(p, CreatePermission),
		SelfCreate: slices.Contains(p, SelfCreatePermission),
		Read:       slices.Contains(p, ReadPermission),
		SelfRead:   slices.Contains(p, SelfReadPermission),
		Update:     slices.Contains(p, UpdatePermission),
		SelfUpdate: slices.Contains(p, SelfUpdatePermission),
		Delete:     slices.Contains(p, DeletePermission),
		SelfDelete: slices.Contains(p, SelfDeletePermission),
	}
}

func (required *PermissionsTable) Permit(permitted *PermissionsTable) *Error {
	if required.Admin && !permitted.Admin {
		return InsufficientPermissions
	}

	if required.Moderator && (!permitted.Moderator || !permitted.Admin) {
		return InsufficientPermissions
	}

	// Admins and moderators can do all CRUD operations (even if corresponding permissions are not specified for them)
	if permitted.Admin || permitted.Moderator {
		return nil
	}

	// CRUD operations

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
