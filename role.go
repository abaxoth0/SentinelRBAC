package rbac

type Role struct {
	Name        string       `json:"name"`
	Permissions []Permission `json:"permissions"`
}
