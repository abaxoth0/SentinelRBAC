package rbac

type action string

func (a action) String() string {
	return string(a)
}
