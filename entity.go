package rbac

import (
	"errors"
)

type Entity struct {
	Name string
	// Action's "Permissions" is required permissions for this specific action
	actions   map[Action]*Permissions
	authorize AuthorizationFunc
}

// Creates a new entity with the specified name.
//
// This function initializes an empty map for actions and sets the default
// authorization function to "rbac.Authorize".
func NewEntity(name string) *Entity {
	return &Entity{
		Name:      name,
		actions:   make(map[Action]*Permissions),
		authorize: Authorize,
	}
}

func (e *Entity) NewAction(name string, requiredPermissions *Permissions) Action {
	act := Action(name)

	if e.HasAction(act) {
		panic("action \"" + name + "\" already exists in \"" + e.Name + "\" entity")
	}

	e.actions[act] = requiredPermissions

	return act
}

func (e *Entity) RemoveAction(act Action) {
	delete(e.actions, act)
}

func (e *Entity) HasAction(act Action) bool {
	_, ok := e.actions[act]

	return ok
}

// Changes the authorization function of the entity.
//
// The default authorization function is "rbac.Authorize".
func (e *Entity) SetAuthorizationFunc(fn AuthorizationFunc) {
	if fn == nil {
		panic("authorization function can't be nil")
	}

	e.authorize = fn
}

func (e *Entity) AuthorizeAction(act Action, resource *Resource, rolesNames []string) error {
	requiredPermissions := e.actions[act]

	if requiredPermissions == nil {
		return errors.New("action \"" + act.String() + "\" wasn't found in entity \"" + e.Name + "\"")
	}

	permitted := false

	for _, roleName := range rolesNames {
		permissions := resource.Permissions[roleName]

		if permissions == nil {
			return NewError("permissions of resource \"" + resource.Name + "\" for \"" + roleName + "\" role is not defined")
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
