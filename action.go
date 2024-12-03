package rbac

type Action struct {
	Name                string
	RequiredPermissions *Permissions
}
