package rbac

import "errors"

type Entity struct {
	Name string
}

// Creates a new entity with the specified name.
func NewEntity(name string) Entity {
	return Entity{
		Name: name,
	}
}

func (e Entity) prefix(act string) Action {
	return Action(e.Name + "." + act)
}

// Creates action with given name for specified entity.
// Will return zero value of Action and error if action with this name already exists on this entity.
func (e Entity) NewAction(name string, requiredPermissions Permissions) (Action, error) {
	act := e.prefix(name)

	if e.HasAction(act) {
		return "", errors.New("action \"" + name + "\" already exists in \"" + e.Name + "\" entity")
	}

	actions[act] = requiredPermissions

	return act, nil
}

func (e Entity) RemoveAction(act Action) {
	delete(actions, e.prefix(act.String()))
}

func (e Entity) HasAction(act Action) bool {
	_, ok := actions[e.prefix(act.String())]

	return ok
}

