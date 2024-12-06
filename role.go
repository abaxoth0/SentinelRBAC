package rbac

type Role struct {
	Name        string       `json:"name"`
	Permissions *Permissions `json:"permissions"`
}
