package rbac

import "errors"

type Entity struct {
	Name 	string
	actions	map[Action]Permissions
	rolesPermissions map[string]Permissions
}

// Creates a new entity with the specified name.
func NewEntity(name string, roles []Role) Entity {
	entity := &Entity{
		Name: name,
		actions: make(map[Action]Permissions),
		rolesPermissions: make(map[string]Permissions),
	}

	for _, role := range roles {
		entity.rolesPermissions[role.Name] = role.Permissions
	}

	return *entity
}

// Creates action with given name for specified entity.
// Will return zero value of Action and error if action with this name already exists on this entity.
func (e Entity) NewAction(name string, requiredPermissions Permissions) (Action, error) {
	act := Action(name)

	if e.HasAction(act) {
		return "", errors.New("\""+e.Name+"\" entity already has \""+name+"\" action")
	}

	e.actions[act] = requiredPermissions

	return act, nil
}

func (e Entity) RemoveAction(act Action) {
	delete(e.actions, act)
}

func (e Entity) HasAction(act Action) bool {
	_, ok := e.actions[act]
	return ok
}

