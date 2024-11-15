package rbac

import "slices"

const NoneRole string = "none"

// TODO refactor all that

func IsAdmin(role *Role) bool {
	return slices.Contains(role.Permissions, AdminPermissionTag)
}

func IsModerator(role *Role) bool {
	return slices.Contains(role.Permissions, ModeratorPermissionTag)
}

func ParseRole(roleName string) (*Role, *Error) {
	if !IsSchemaLoaded() {
		panic("RBAC is not loaded")
	}

	// TODO Now works incorrect.
	//  Need to also search in services
	for _, schemaRole := range Schema.DefaultRoles {
		if schemaRole.Name == roleName {
			return schemaRole, nil
		}
	}

	return nil, NewError("Роль \"" + roleName + "\" не надена")
}

func GetServiceRoles(serviceID string) ([]*Role, *Error) {
	if !IsSchemaLoaded() {
		panic("RBAC is not loaded")
	}

	var service *Service = nil

	for _, schemaService := range Schema.Services {
		if schemaService.ID == serviceID {
			service = schemaService
			break
		}
	}

	if service == nil {
		return nil, NewError("service with id \"" + serviceID + "\" wasn't found")
	}

	if len(service.Roles) == 0 {
		return Schema.DefaultRoles, nil
	}

	roles := []*Role{}

	// TODO Try to optimize it.
	// Although it's not so important, RBAC schema isn't big enoungh to see a real difference in performance.
	for _, serviceRole := range service.Roles {
		for _, globalRole := range Schema.DefaultRoles {
			if serviceRole.Name == globalRole.Name {
				roles = append(roles, serviceRole)
			} else {
				roles = append(roles, globalRole)
			}
		}
	}

	return roles, nil
}

// This works only for this service
func GetAuthRole(roleName string) (*Role, *Error) {
	if !IsSchemaLoaded() {
		panic("RBAC is not loaded")
	}

	for _, globalRole := range Schema.DefaultRoles {
		if globalRole.Name == roleName {
			return globalRole, nil
		}
	}

	return nil, NewError("role with name \"" + roleName + "\" wasn't found")
}
