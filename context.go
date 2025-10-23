package rbac

type AuthorizationContext struct {
	Entity   *Entity
	Action   Action
	Resource *Resource
}

func (ctx *AuthorizationContext) String() string {
	return ctx.Entity.name + ":" + ctx.Action.String() + ":" + ctx.Resource.name
}

func NewAuthorizationContext(entity *Entity, act Action, resource *Resource) AuthorizationContext {
	return AuthorizationContext{
		Entity:   entity,
		Action:   act,
		Resource: resource,
	}
}
