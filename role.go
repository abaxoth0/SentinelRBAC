package rbac

type Role struct {
	Name        string          `json:"name"`
	Permissions []PermissionTag `json:"permissions"`
}
