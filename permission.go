package rbac

type PermissionTag string

func (p PermissionTag) String() string {
	return string(p)
}

const CreateTag PermissionTag = "CREATE"
const SelfCreateTag PermissionTag = "SELF-CREATE"

const ReadTag PermissionTag = "READ"
const SelfReadTag PermissionTag = "SELF-READ"

const UpdateTag PermissionTag = "UPDATE"
const SelfUpdateTag PermissionTag = "SELF-UPDATE"

const DeleteTag PermissionTag = "DELETE"
const SelfDeleteTag PermissionTag = "SELF-DELETE"

var tags [8]PermissionTag = [8]PermissionTag{
	CreateTag,
	SelfCreateTag,
	ReadTag,
	SelfReadTag,
	UpdateTag,
	SelfUpdateTag,
	DeleteTag,
	SelfDeleteTag,
}

func Tags() [8]PermissionTag {
	return tags
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
}

var InsufficientPermissions *Error = NewError("Insufficient permissions to perform this action")

// Converts a slice of permission tags into a permissions.
//
// It doesn't check if a tag is valid or not, it just sets the corresponding
// boolean field of the Permissions to true if the tag is present in the slice.
func ParseTags(p []PermissionTag) *Permissions {
	var r = Permissions{}

	for _, tag := range p {
		switch tag {
		case CreateTag:
			r.Create = true
		case SelfCreateTag:
			r.SelfCreate = true
		case ReadTag:
			r.Read = true
		case SelfReadTag:
			r.SelfRead = true
		case UpdateTag:
			r.Update = true
		case SelfUpdateTag:
			r.SelfUpdate = true
		case DeleteTag:
			r.Delete = true
		case SelfDeleteTag:
			r.SelfDelete = true
		default:
			panic("invalid permission tag: " + tag.String())
		}
	}

	return &r
}
