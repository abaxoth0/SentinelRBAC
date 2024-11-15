package rbac

import "slices"

type Role struct {
	Name        string          `json:"name"`
	Permissions []PermissionTag `json:"permissions"`
}

const NoneRole string = "none"

func IsAdmin(role *Role) bool {
	return slices.Contains(role.Permissions, AdminPermissionTag)
}

func IsModerator(role *Role) bool {
	return slices.Contains(role.Permissions, ModeratorPermissionTag)
}

func ParseRole(roleName string, service *Service) (*Role, *Error) {
	if !IsSchemaLoaded() {
		return nil, NewError("RBAC is not loaded")
	}

	if CurrentService == nil {
		return nil, NewError("CurrentService is not set")
	}

	for _, role := range service.Roles {
		if role.Name == roleName {
			return role, nil
		}
	}

	return nil, NewError("Роль \"" + roleName + "\" не надена")
}
