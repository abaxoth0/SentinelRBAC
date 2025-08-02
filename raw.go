package rbac

import (
	"fmt"
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

func normalizeDefaultRoles(roles []Role, defaultRolesNames []string) ([]Role, error) {
    defaultRoles := []Role{}

    for _, role := range roles {
        if slices.Contains(defaultRolesNames, role.Name) {
            defaultRoles = append(defaultRoles, role)
        }
    }

    // TODO deduplicate that? (check validateDefaultRoles())
    if len(defaultRoles) != len(defaultRolesNames) {
        outer:
        for _, roleName := range defaultRolesNames {
            for _, role := range defaultRoles {
                if roleName == role.Name {
                    continue outer;
                }

            }

            return nil, fmt.Errorf(
                "Invalid role '%s'. This role doesn't exists in Schema roles",
                roleName,
            )
        }
    }

    return defaultRoles, nil
}

// Creates new Schema based on self.
func (s *rawSchema) Normalize() (Schema, error) {
    Debug.Log("Normalizing schema...")

    schema := Schema{}

    var err error

    schema.ID = s.ID
    schema.Roles = normalizeRoles(s.Roles)
    schema.DefaultRoles, err = normalizeDefaultRoles(schema.Roles, s.DefaultRolesNames)
    if err != nil {
        return Schema{}, err
    }

    Debug.Log("Normalizing schema: OK")

    return schema, nil
}

func (s *rawSchema) NormalizeAndValidate() (Schema, error) {
    var zero Schema

    schema, err :=s.Normalize()
    if err != nil {
        return zero, err
    }

    if err := ValidateSchema(&schema); err != nil {
        return zero, err
    }

    return schema, nil
}

type rawHost struct {
    DefaultRolesNames []string     `json:"default-roles,omitempty"`
    GlobalRoles       []*rawRole   `json:"roles"`
	Schemas           []*rawSchema `json:"schemas"`
}

// Creates new Host based on self.
func (h *rawHost) Normalize() (Host, error) {
    var zero Host

    Debug.Log("Normalizing host...")

    host := Host{}

    host.Schemas = make([]Schema, len(h.Schemas))

    for i, rawSchema := range h.Schemas {
        roles := normalizeRoles(rawSchema.Roles)

        defaultRoles, err := normalizeDefaultRoles(
            roles,
            rawSchema.DefaultRolesNames,
        )
        if err != nil {
            return zero, err
        }

        host.Schemas[i] = NewSchema(rawSchema.ID, roles, defaultRoles)
    }

    var err error

    host.GlobalRoles = normalizeRoles(h.GlobalRoles)
    host.DefaultRoles, err = normalizeDefaultRoles(host.GlobalRoles, h.DefaultRolesNames)
    if err != nil {
        return zero, err
    }

    Debug.Log("Normalizing host: OK")

    return host, nil
}

func (h rawHost) NormalizeAndValidate() (Host, error) {
    var zero Host

    host, err := h.Normalize()
    if err != nil {
        return zero, err
    }

    if err := ValidateHost(&host); err != nil {
        return zero, err
    }

    return host, nil
}

