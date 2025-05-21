package rbac

import (
	"slices"
)

// "raw" structs are design to be used by host and schema to be able being initialized from files.
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
    ID                string     `json:"id"`
    Name              string     `json:"name"`
    Roles             []*rawRole `json:"roles,omitempty"`
    DefaultRolesNames []string   `json:"default-roles,omitempty"`
}

func normalizeRoles(rawRoles []*rawRole) []Role {
    roles := make([]Role, len(rawRoles))

    for i, rawRole := range rawRoles {
        roles[i] = NewRole(
            rawRole.Name,
            rawRole.Permissions.ToBitmask(),
        )
    }

    return roles
}

func normalizeDefaultRoles(roles []Role, defaultRolesNames []string) []Role {
    defaultRoles := []Role{}

    for i, role := range roles {
        if slices.Contains(defaultRolesNames, role.Name) {
            defaultRoles = append(defaultRoles, roles[i])
        }
    }

    return defaultRoles
}

// Creates new Schema based on self.
func (s *rawSchema) Normalize() *Schema {
    debugLog("[ RBAC ] Normalizing schema...")

    var schema = new(Schema)

    schema.ID = s.ID
    schema.Name = s.Name
    schema.Roles = normalizeRoles(s.Roles)
    schema.DefaultRoles = normalizeDefaultRoles(schema.Roles, s.DefaultRolesNames)

    debugLog("[ RBAC ] Normalizing schema: OK")

    return schema
}

type rawHost struct {
    DefaultRolesNames []string     `json:"default-roles,omitempty"`
    GlobalRoles       []*rawRole   `json:"roles"`
	Schemas           []*rawSchema `json:"schemas"`
}

// Creates new Host based on self.
func (h *rawHost) Normalize() *Host {
    debugLog("[ RBAC ] Normalizing host...")

    var host = new(Host)

    host.Schemas = make([]Schema, len(h.Schemas))

    for i, rawSchema := range h.Schemas {
        host.Schemas[i] = NewSchema(
            rawSchema.ID,
            rawSchema.Name,
            normalizeRoles(rawSchema.Roles),
            normalizeDefaultRoles(
                host.Schemas[i].Roles,
                rawSchema.DefaultRolesNames,
            ),
        )
    }

    host.GlobalRoles = normalizeRoles(h.GlobalRoles)
    host.DefaultRoles = normalizeDefaultRoles(host.GlobalRoles, h.DefaultRolesNames)

    debugLog("[ RBAC ] Normalizing host: OK")

    return host
}

