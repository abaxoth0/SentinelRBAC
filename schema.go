package rbac

type Schema struct {
    ID           string
    Name         string
    Roles        []Role
    DefaultRoles []Role
}

func NewSchema(id string, name string, roles []Role, defaultRoles []Role) Schema {
	return Schema{
        ID:    id,
        Name:  name,
        Roles: roles,
        DefaultRoles: defaultRoles,
	}
}

func (schema *Schema) ParseRole(roleName string) (Role, *Error) {
	for _, role := range schema.Roles {
		if role.Name == roleName {
			return role, nil
		}
	}

	return Role{}, NewError("Role \"" + roleName + "\" wasn't found in schema \"" + schema.Name + "\"")
}

func (s *Schema) Validate() error {
    debugLog("[ RBAC ] Validating schema...")

    if err := validateDefaultRoles(s.Roles, s.DefaultRoles); err != nil {
        return err
    }

    debugLog("[ RBAC ] Validating schema: OK")

    return nil
}

// Reads and parses RBAC schema from file at the specified path.
// After loading and normalizing, it validates schema and returns an error if any of them were detected.
func LoadSchema(path string) (Schema, error) {
    var zero Schema

    raw, err := load[rawSchema](path)
    if err != nil {
        return zero, err
    }

    schema := raw.Normalize()

	if err = schema.Validate(); err != nil {
		return zero, err
	}

	return *schema, nil
}

