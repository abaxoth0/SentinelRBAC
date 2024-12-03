package rbac

type Resource struct {
	Name        string
	Permissions map[string]*Permissions
}
