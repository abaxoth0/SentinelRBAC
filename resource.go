package rbac

type resource struct {
	Name        string
	Permissions map[string]*Permissions
}

func NewResource(name string, roles []*Role) *resource {
	r := &resource{
		Name:        name,
		Permissions: make(map[string]*Permissions),
	}

	for _, role := range roles {
		r.Permissions[role.Name] = role.Permissions
	}

	return r
}
