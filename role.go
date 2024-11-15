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

func GetServiceRoles(serviceID string) ([]*Role, *Error) {
	if !IsSchemaLoaded() {
		return nil, NewError("RBAC is not loaded")
	}

	if serviceID == "" {
		return nil, NewError("Missing service id")
	}

	for _, service := range Schema.Services {
		if service.ID == serviceID {
			return service.Roles, nil
		}
	}

	return nil, NewError("service with id \"" + serviceID + "\" wasn't found")
}
