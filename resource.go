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
func (r *Resource) Authorize(act Action, rolesNames []string) error {
    requiredPermissions := actions[act]

    if requiredPermissions == 0 {
        return errors.New("action \"" + act.String() + "\" wasn't found")
    }

    mergredPermissions := 0

    for _, roleName := range rolesNames {
        mergredPermissions |= r.RolesPermissions[roleName]
    }

    if err := authorize(requiredPermissions, mergredPermissions); err == nil {
        return nil
    }

    return InsufficientPermissions
}

