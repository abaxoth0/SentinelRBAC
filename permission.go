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

type permissions struct {
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

func VerifyPermissions(required *permissions, permitted *permissions, targetRole *Role) *Error {
	isTargetModerator := slices.Contains(targetRole.Permissions, ModeratorPermissionTag)
	isTargetAdmin := slices.Contains(targetRole.Permissions, AdminPermissionTag)

	if (required.Delete || required.SelfDelete) && isTargetAdmin {
		return NewError("Невозможно удалить пользователя с ролью администратора. (Обратитесь напрямую в базу данных)")
	}

	if isTargetModerator && !permitted.Admin && (required.Update || required.Delete) {
		return InsufficientPermission
	}

	if required.Admin && !permitted.Admin {
		return InsufficientPermission
	}

	if required.Moderator && (!permitted.Moderator || !permitted.Admin) {
		return InsufficientPermission
	}

	if permitted.Admin || permitted.Moderator {
		return nil
	}

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

func GetPermissions(required []PermissionTag, targetRole *Role) (*permissions, *permissions) {
	targetPermissions := &permissions{
		Admin:      slices.Contains(targetRole.Permissions, AdminPermissionTag),
		Moderator:  slices.Contains(targetRole.Permissions, ModeratorPermissionTag),
		Create:     slices.Contains(targetRole.Permissions, CreatePermissionTag),
		SelfCreate: slices.Contains(targetRole.Permissions, SelfCreatePermissionTag),
		Read:       slices.Contains(targetRole.Permissions, ReadPermissionTag),
		SelfRead:   slices.Contains(targetRole.Permissions, SelfReadPermissionTag),
		Update:     slices.Contains(targetRole.Permissions, UpdatePermissionTag),
		SelfUpdate: slices.Contains(targetRole.Permissions, SelfUpdatePermissionTag),
		Delete:     slices.Contains(targetRole.Permissions, DeletePermissionTag),
		SelfDelete: slices.Contains(targetRole.Permissions, SelfDeletePermissionTag),
	}

	requiredPermissions := &permissions{
		Admin:      slices.Contains(required, AdminPermissionTag),
		Moderator:  slices.Contains(required, ModeratorPermissionTag),
		Create:     slices.Contains(required, CreatePermissionTag),
		SelfCreate: slices.Contains(required, SelfCreatePermissionTag),
		Read:       slices.Contains(required, ReadPermissionTag),
		SelfRead:   slices.Contains(required, SelfReadPermissionTag),
		Update:     slices.Contains(required, UpdatePermissionTag),
		SelfUpdate: slices.Contains(required, SelfUpdatePermissionTag),
		Delete:     slices.Contains(required, DeletePermissionTag),
		SelfDelete: slices.Contains(required, SelfDeletePermissionTag),
	}

	return targetPermissions, requiredPermissions
}
