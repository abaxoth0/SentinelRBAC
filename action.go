package rbac

type Action string

func (a Action) String() string {
	return string(a)
}

