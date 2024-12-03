package rbac

type Schema struct {
	ID    string  `json:"id"`
	Name  string  `json:"name"`
	Roles []*Role `json:"roles,omitempty"`
}

func (schema *Schema) ParseRole(roleName string) (*Role, *Error) {
	for _, role := range schema.Roles {
		if role.Name == roleName {
			return role, nil
		}
	}

	return nil, NewError("Role \"" + roleName + "\" wasn't found in schema \"" + schema.Name + "\"")
}
