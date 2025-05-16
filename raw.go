package rbac

// "raw" structs are design to be used by host to parse configuration file.
// They are more user-friendly, but also more "heavy".
//
// So for example - rawPermissions is just a struct which consists of flags,
// instead original Permissions is bitmask.
// Of course rawPermissions more convenient and readable, but also more slow.
// For example:
// For authz using Permissions used bitwise operations which are extrimely fast,
// but using rawPermissions the only way is to check all flag one-by-one in 'if' statements.

type rawPermissions struct {
	Create     bool `json:"create"`
	SelfCreate bool `json:"self-create"`
	Read       bool `json:"read"`
	SelfRead   bool `json:"self-read"`
	Update     bool `json:"update"`
	SelfUpdate bool `json:"self-update"`
	Delete     bool `json:"delete"`
	SelfDelete bool `json:"self-delete"`
}

func (r rawPermissions) ToBitmask() Permissions {
    var permissions Permissions

    if r.Create {
        permissions |= CreatePermission
    }
    if r.SelfCreate {
        permissions |= SelfCreatePermission
    }
    if r.Read {
        permissions |= ReadPermission
    }
    if r.SelfRead {
        permissions |= SelfReadPermission
    }
    if r.Update {
        permissions |= UpdatePermission
    }
    if r.SelfUpdate {
        permissions |= SelfUpdatePermission
    }
    if r.Delete {
        permissions |= DeletePermission
    }
    if r.SelfDelete {
        permissions |= SelfDeletePermission
    }

    return permissions
}

type rawRole struct {
    Name        string          `json:"name"`
    Permissions *rawPermissions `json:"permissions"`
}

type rawSchema struct {
    ID    string     `json:"id"`
    Name  string     `json:"name"`
    Roles []*rawRole `json:"roles,omitempty"`
}

type rawHost struct {
	DefaultRolesNames []string     `json:"default-roles,omitempty"`
	Roles             []*rawRole   `json:"roles"`
	Schemas           []*rawSchema `json:"schemas"`
}

// Creates new Host based on self.
func (h *rawHost) Normalize() Host {
    var host Host

    host.DefaultRolesNames = h.DefaultRolesNames
    host.Schemas = make([]*Schema, len(h.Schemas))

    for i, rawSchema := range h.Schemas {
        host.Schemas[i] = NewSchema(
            rawSchema.ID,
            rawSchema.Name,
            make([]*Role, len(rawSchema.Roles)),
        )

        for j, rawRole := range rawSchema.Roles {
            host.Schemas[i].Roles[j] = NewRole(
                rawRole.Name,
                rawRole.Permissions.ToBitmask(),
            )
        }
    }

    host.Roles = make([]*Role, len(h.Roles))

    for i, rawRole := range h.Roles {
        host.Roles[i] = NewRole(
            rawRole.Name,
            rawRole.Permissions.ToBitmask(),
        )
    }

    return host
}

