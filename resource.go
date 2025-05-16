package rbac

type Resource struct {
	Name             string
	RolesPermissions map[string]Permissions
}

func NewResource(name string, roles []*Role) *Resource {
	r := &Resource{
		Name:        name,
		RolesPermissions: make(map[string]Permissions),
	}

	for _, role := range roles {
		r.RolesPermissions[role.Name] = role.Permissions
	}

	return r
}

