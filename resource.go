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
		// Deep copy, so if permissions will be changed in resource, it won't affect "role"
		p := *role.Permissions

		r.Permissions[role.Name] = &p
	}

	return r
}
