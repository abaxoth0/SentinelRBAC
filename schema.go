package rbac

type Schema struct {
	ID               string
	Roles            []Role
	DefaultRoles     []Role
	Entities         []Entity
	Resources        []Resource
	ActionGatePolicy ActionGatePolicy
}

func NewSchema(id string, roles []Role, defaultRoles []Role, agp ActionGatePolicy) Schema {
	return Schema{
		ID:               id,
		Roles:            roles,
		DefaultRoles:     defaultRoles,
		ActionGatePolicy: agp,
	}
}

func (schema *Schema) ParseRole(roleName string) (Role, *Error) {
	for _, role := range schema.Roles {
		if role.Name == roleName {
			return role, nil
		}
	}

	return Role{}, NewError("\"" + schema.ID + "\" schema doesn't have \"" + roleName + "\" role")
}

// Reads and parses RBAC schema from file at the specified path.
// After loading and normalizing, it validates schema and returns an error if any of them were detected.
func LoadSchema(path string) (Schema, error) {
	schema, err := load[Schema, *rawSchema](path, nil)
	if err != nil {
		return Schema{}, err
	}

	return schema, nil
}
