package rbac

import (
	"errors"
)

type entity struct {
	Name              string
	AuthorizationFunc AuthFunc
	actions           map[string]Action
}

func NewEntity(name string) *entity {
	return &entity{
		Name:              name,
		AuthorizationFunc: Authorize,
		actions:           make(map[string]Action),
	}
}

func (s *entity) RegisterAction(action Action) {
	s.actions[action.Name] = action
}

func (s *entity) RemoveAction(actionName string) {
	delete(s.actions, actionName)
}

func (s *entity) HasAction(actionName string) bool {
	_, ok := s.actions[actionName]

	return ok
}

func (s *entity) AuthorizeAction(userRole *Role, action Action, resource *Resource) error {
	if !s.HasAction(action.Name) {
		return errors.New("action \"" + action.Name + "\" wasn't found in entity \"" + s.Name + "\"")
	}

	requiredPermissions := resource.Permissions[userRole.Name]

	if requiredPermissions == nil {
		return NewError("resource permissions is not defined")
	}

	return Authorize(action.RequiredPermissions, resource.Permissions[userRole.Name])
}
