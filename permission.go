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
