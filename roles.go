package rbac

import "fmt"

// creates a map for quick lookups by role name.
func buildRoleMap(roles []Role) map[string]Role {
	roleMap := make(map[string]Role, len(roles))
	for _, role := range roles {
		roleMap[role.Name] = role
	}
	return roleMap
}

// returns a slice of roles matching the provided names.
// Returns an error if any of the names do not exist in the role map.
func rolesByNames(roleMap map[string]Role, names []string) ([]Role, error) {
	result := make([]Role, 0, len(names))

	for _, name := range names {
		role, ok := roleMap[name]
		if !ok {
			return nil, fmt.Errorf("Invalid role '%s'. This role doesn't exist in Schema roles", name)
		}

		result = append(result, role)
	}

	return result, nil
}
