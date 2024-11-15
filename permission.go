package rbac

import (
	"slices"
)

type PermissionTag string

func (p PermissionTag) String() string {
	return string(p)
}

const CreatePermissionTag PermissionTag = "C"
const SelfCreatePermissionTag PermissionTag = "SC"

const ReadPermissionTag PermissionTag = "R"
const SelfReadPermissionTag PermissionTag = "SR"

const UpdatePermissionTag PermissionTag = "U"
const SelfUpdatePermissionTag PermissionTag = "SU"

const DeletePermissionTag PermissionTag = "D"
const SelfDeletePermissionTag PermissionTag = "SD"

const ModeratorPermissionTag PermissionTag = "M"
const AdminPermissionTag PermissionTag = "A"

var PermissionTags []PermissionTag = []PermissionTag{
	CreatePermissionTag,
	SelfCreatePermissionTag,
	ReadPermissionTag,
	SelfReadPermissionTag,
	UpdatePermissionTag,
	SelfUpdatePermissionTag,
	DeletePermissionTag,
	SelfDeletePermissionTag,
	ModeratorPermissionTag,
	AdminPermissionTag,
}

type Permissions struct {
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
}

var InsufficientPermission *Error = NewError("Недостаточно прав для выполнения данной операции")

// Converts a slice of PermissionTag into a *permissions.
//
// It doesn't check if a permission is valid or not, it just sets the corresponding
// boolean field of the *permissions to true if the permission is present in the
// slice.
func GetPermissions(tags []PermissionTag) *Permissions {
	return &Permissions{
		Admin:      slices.Contains(tags, AdminPermissionTag),
		Moderator:  slices.Contains(tags, ModeratorPermissionTag),
		Create:     slices.Contains(tags, CreatePermissionTag),
		SelfCreate: slices.Contains(tags, SelfCreatePermissionTag),
		Read:       slices.Contains(tags, ReadPermissionTag),
		SelfRead:   slices.Contains(tags, SelfReadPermissionTag),
		Update:     slices.Contains(tags, UpdatePermissionTag),
		SelfUpdate: slices.Contains(tags, SelfUpdatePermissionTag),
		Delete:     slices.Contains(tags, DeletePermissionTag),
		SelfDelete: slices.Contains(tags, SelfDeletePermissionTag),
	}
}

func VerifyPermissions(required *Permissions, permitted *Permissions) *Error {
	if required.Admin && !permitted.Admin {
		return InsufficientPermission
	}

	if required.Moderator && (!permitted.Moderator || !permitted.Admin) {
		return InsufficientPermission
	}

	// Admins and moderators can do all CRUD operations (even if corresponding permissions are not specified for them)
	if permitted.Admin || permitted.Moderator {
		return nil
	}

	// CRUD operations

	if required.Create && (!permitted.Create) {
		return InsufficientPermission
	}

	if required.SelfCreate && (!permitted.Create || !permitted.SelfCreate) {
		return InsufficientPermission
	}

	if required.Create && (!permitted.Create) {
		return InsufficientPermission
	}

	if required.SelfRead && (!permitted.Read || !permitted.SelfRead) {
		return InsufficientPermission
	}

	if required.Update && (!permitted.Update) {
		return InsufficientPermission
	}

	if required.SelfUpdate && (!permitted.Update || !permitted.SelfUpdate) {
		return InsufficientPermission
	}

	if required.Delete && (!permitted.Delete) {
		return InsufficientPermission
	}

	if required.SelfDelete && (!permitted.Delete || !permitted.SelfDelete) {
		return InsufficientPermission
	}

	return nil
}
