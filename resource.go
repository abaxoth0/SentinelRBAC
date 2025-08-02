package rbac

import "errors"

type Resource struct {
	Name             string
	RolesPermissions map[string]Permissions
}

func NewResource(name string, roles []Role) *Resource {
	r := &Resource{
		Name:        name,
		RolesPermissions: make(map[string]Permissions),
	}

	for _, role := range roles {
		r.RolesPermissions[role.Name] = role.Permissions
	}

	return r
}

// Checks if the user has sufficient permissions to perform an action on this resource.
//
// Returns an error if any of the required permissions for the action are not covered by given roles.
func (r *Resource) Authorize(entity Entity, act Action, rolesNames []string) error {
    if !entity.HasAction(act) {
        return errors.New("\""+act.String()+"\" entity doesn't have \""+act.String()+"\" action")
    }

	requiredPermissions := entity.actions[act]
    mergredPermissions := Permissions(0)

    for _, roleName := range rolesNames {
        mergredPermissions |= r.RolesPermissions[roleName]
    }

    if err := authorize(requiredPermissions, mergredPermissions); err == nil {
        return nil
    }

    return InsufficientPermissions
}

