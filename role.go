package rbac

type Role struct {
	Name        string       `json:"name"`
	Permissions *Permissions `json:"permissions"`
}

func NewRole(name string, permissions *Permissions) *Role {
	return &Role{
		Name:        name,
		Permissions: permissions,
	}
}
