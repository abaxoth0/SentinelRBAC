package rbac

type Resource struct {
	name 			 string
}

func NewResource(name string) *Resource {
	return &Resource{
		name: name,
	}
}

func (r *Resource) Name() string {
	return r.name
}

// Checks if the user has sufficient permissions to perform an action on this resource.
//
// Returns an error if any of the required permissions for the action are not covered by given roles.
func (r *Resource) Authorize(entity Entity, act Action, roles []Role, AGP *ActionGatePolicy) *Error {
    if !entity.HasAction(act) {
        return EntityDoesNotHaveSuchAction
    }

	if AGP != nil {
		if rule, ok := AGP.GetRule(&entity, act, r); ok {
			bypass, err := rule.Apply(act, roles)
			if err != nil {
				return err
			}
			if bypass {
				return nil
			}
		}
	}

	requiredPermissions := entity.actions[act]
    mergredPermissions := Permissions(0)

    for _, role := range roles {
        mergredPermissions |= role.Permissions
    }

    if err := authorize(requiredPermissions, mergredPermissions); err == nil {
        return nil
    }

    return InsufficientPermissions
}

