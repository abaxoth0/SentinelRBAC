package rbac

import (
	"errors"
)

type entity struct {
	Name string
	// Action's "Permissions" is required permissions for this specific action
	actions   map[action]*Permissions
	authorize AuthorizationFunc
}

// Creates a new entity with the specified name.
//
// This function initializes an empty map for actions and sets the default
// authorization function to "rbac.Authorize".
func NewEntity(name string) *entity {
	return &entity{
		Name:      name,
		actions:   make(map[action]*Permissions),
		authorize: Authorize,
	}
}

func (e *entity) NewAction(name string, requiredPermissions *Permissions) action {
	act := action(name)

	if e.HasAction(act) {
		panic("action \"" + name + "\" already exists in \"" + e.Name + "\" entity")
	}

	e.actions[act] = requiredPermissions

	return act
}

func (e *entity) RemoveAction(act action) {
	delete(e.actions, act)
}

func (e *entity) HasAction(act action) bool {
	_, ok := e.actions[act]

	return ok
}

// Changes the authorization function of the entity.
//
// The default authorization function is "rbac.Authorize".
func (e *entity) SetAuthorizationFunc(fn AuthorizationFunc) {
	if fn == nil {
		panic("authorization function can't be nil")
	}

	e.authorize = fn
}

func (e *entity) AuthorizeAction(act action, resource *Resource, userRoles ...*Role) error {
	requiredPermissions := e.actions[act]

	if requiredPermissions == nil {
		return errors.New("action \"" + act.String() + "\" wasn't found in entity \"" + e.Name + "\"")
	}

	permitted := false

	for _, role := range userRoles {
		permissions := resource.Permissions[role.Name]

		if permissions == nil {
			return NewError("permissions of resource \"" + resource.Name + "\" for \"" + role.Name + "\" role is not defined")
		}

		if err := e.authorize(requiredPermissions, permissions); err == nil {
			permitted = true
			break
		}
	}

	if !permitted {
		return InsufficientPermissions
	}

	return nil
}
