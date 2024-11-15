package rbac

type Role struct {
	Name        string          `json:"name"`
	Permissions []PermissionTag `json:"permissions"`
}

type Service struct {
	ID    string  `json:"id"`
	Name  string  `json:"name"`
	Roles []*Role `json:"roles,omitempty"`
}
