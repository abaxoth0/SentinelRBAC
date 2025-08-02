package rbac

import "errors"

type Entity struct {
	Name 	string
	actions	map[Action]Permissions
}

// Creates a new entity with the specified name.
func NewEntity(name string) Entity {
	return Entity{
		Name: name,
		actions: make(map[Action]Permissions),
	}
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

