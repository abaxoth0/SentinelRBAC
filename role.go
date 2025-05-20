package rbac

type Role struct {
	Name        string
	Permissions Permissions
}

func NewRole(name string, permissions Permissions) Role {
	return Role{
		Name:        name,
		Permissions: permissions,
	}
}

func GetRolesNames(roles []Role) []string {
	names := make([]string, len(roles))

	for i, role := range roles {
		names[i] = role.Name
	}

	return names
}

