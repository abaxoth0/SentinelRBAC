package rbac

type Resource struct {
	name string
}

func NewResource(name string) *Resource {
	return &Resource{
		name: name,
	}
}

func (r *Resource) Name() string {
	return r.name
}
