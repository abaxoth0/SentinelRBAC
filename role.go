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
