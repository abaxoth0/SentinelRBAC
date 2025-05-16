package rbac

type Action string

func (a Action) String() string {
	return string(a)
}

var actions = make(map[Action]Permissions)

