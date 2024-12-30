package rbac

type Entity struct {
	Name string
}

// Creates a new entity with the specified name.
//
// This function initializes an empty map for actions and sets the default
// authorization function to "rbac.Authorize".
func NewEntity(name string) *Entity {
	return &Entity{
		Name: name,
	}
}

func (e *Entity) prefix(act string) Action {
	return Action(e.Name + "." + act)
}

func (e *Entity) NewAction(name string, requiredPermissions *Permissions) Action {
	act := e.prefix(name)

	if e.HasAction(act) {
		panic("action \"" + name + "\" already exists in \"" + e.Name + "\" entity")
	}

	actions[act] = requiredPermissions

	return act
}

func (e *Entity) RemoveAction(act Action) {
	delete(actions, e.prefix(act.String()))
}

func (e *Entity) HasAction(act Action) bool {
	_, ok := actions[e.prefix(act.String())]

	return ok
}
