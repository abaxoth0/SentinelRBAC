package rbac

type Permission string

func (p Permission) String() string {
	return string(p)
}

const CreatePermission Permission = "CREATE"
const SelfCreatePermission Permission = "SELF-CREATE"

const ReadPermission Permission = "READ"
const SelfReadPermission Permission = "SELF-READ"

const UpdatePermission Permission = "UPDATE"
const SelfUpdatePermission Permission = "SELF-UPDATE"

const DeletePermission Permission = "DELETE"
const SelfDeletePermission Permission = "SELF-DELETE"

const ModeratorPermission Permission = "MODERATOR"
const AdminPermission Permission = "ADMIN"
const ServicePermission Permission = "SERVICE"

var permissions [11]Permission = [11]Permission{
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
func Permissions() [11]Permission {
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
func ParsePermissions(p []Permission) *PermissionsTable {
	var r = PermissionsTable{}

	for _, permission := range p {
		switch permission {
		case CreatePermission:
			r.Create = true
		case SelfCreatePermission:
			r.SelfCreate = true
		case ReadPermission:
			r.Read = true
		case SelfReadPermission:
			r.SelfRead = true
		case UpdatePermission:
			r.Update = true
		case SelfUpdatePermission:
			r.SelfUpdate = true
		case DeletePermission:
			r.Delete = true
		case SelfDeletePermission:
			r.SelfDelete = true
		case ModeratorPermission:
			r.Moderator = true
		case AdminPermission:
			r.Admin = true
		case ServicePermission:
			r.Service = true
		default:
			panic("invalid permission: " + permission.String())
		}
	}

	return &r
}

// Checks if the "permitted" permissions are sufficient to satisfy the "required" permissions.
// It returns nil if all "required" permissions are covered by the "permitted" permissions; otherwise,
// it returns an InsufficientPermissions error.
//
// Admins and moderators have full CRUD capabilities regardless of specific permissions.
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
