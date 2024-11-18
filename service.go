package rbac

type Service struct {
	ID    string  `json:"id"`
	Name  string  `json:"name"`
	Roles []*Role `json:"roles,omitempty"`
}

var CurrentService *Service

func GetService(ID string) (*Service, *Error) {
	if !IsSchemaLoaded() {
		return nil, NewError("RBAC is not loaded")
	}

	if ID == "" {
		return nil, NewError("Missing service id")
	}

	for _, service := range Schema.Services {
		if service.ID == ID {
			return service, nil
		}
	}

	return nil, NewError("Service with id \"" + ID + "\" wasn't found")
}

func (service *Service) ParseRole(roleName string) (*Role, *Error) {
	for _, role := range service.Roles {
		if role.Name == roleName {
			return role, nil
		}
	}

	return nil, NewError("Role \"" + roleName + "\" wasn't found in service \"" + service.Name + "\"")
}
