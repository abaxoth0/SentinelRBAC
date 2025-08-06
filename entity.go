package rbac

import "errors"

type Entity struct {
	name 	string
	actions	map[Action]Permissions
}

// Creates a new entity with the specified name.
func NewEntity(name string) Entity {
	return Entity{
		name: name,
		actions: make(map[Action]Permissions),
	}
}

func (e Entity) Name() string {
	return e.name
}

// Creates action with given name for specified entity.
// Will return zero value of Action and error if action with this name already exist on this entity.
func (e Entity) NewAction(name string, requiredPermissions Permissions) (Action, error) {
	act := Action(name)

	if e.HasAction(act) {
		return "", errors.New("\""+e.name+"\" entity already has \""+name+"\" action")
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

func (e Entity) GetRequiredActionPermissions(act Action) (Permissions, bool) {
	p, ok := e.actions[act]
	return p, ok
}

