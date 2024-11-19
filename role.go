package rbac

import "slices"

type Role struct {
	Name        string       `json:"name"`
	Permissions []permission `json:"permissions"`
}

const NoneRole string = "none"

func IsAdmin(role *Role) bool {
	return slices.Contains(role.Permissions, AdminPermission)
}

func IsModerator(role *Role) bool {
	return slices.Contains(role.Permissions, ModeratorPermission)
}

func IsService(role *Role) bool {
	return slices.Contains(role.Permissions, ServicePermission)
}
