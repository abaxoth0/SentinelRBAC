package rbac

type AuthorizationContext struct {
	Entity 	 *Entity
	Action 	 Action
	Resource *Resource
}

func NewAuthorizationContext(entity *Entity, act Action, resource *Resource) AuthorizationContext {
	return AuthorizationContext{
		Entity: entity,
		Action: act,
		Resource: resource,
	}
}

