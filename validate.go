package rbac

import (
	"errors"
	"fmt"
)

func validateDefaultRoles(roles []Role, defaultRoles []Role) error {
    outer:
    for _, defaultRole := range defaultRoles {
        for _, role := range roles {
            if defaultRole.Name == role.Name {
                continue outer;
            }

        }

        return fmt.Errorf(
            "Invalid role '%s'. This role doesn't exists in Schema roles",
            defaultRole.Name,
        )
    }

    return nil
}

func ValidateSchema(schema *Schema) error {
    Debug.Log("[ RBAC ] Validating schema '"+schema.ID+"' ("+schema.ID+")...")

    if err := validateDefaultRoles(schema.Roles, schema.DefaultRoles); err != nil {
        return err
    }

    Debug.Log("[ RBAC ] Validating schema '"+schema.ID+"' ("+schema.ID+"): OK")

    return nil
}

func ValidateHost(host *Host) error {
	Debug.Log("[ RBAC ] Validating host...")

	if len(host.Schemas) == 0 {
		return errors.New("At least one schema must be defined")
	}

    for _, schema := range host.Schemas {
        if err := ValidateSchema(&schema); err != nil {
            return err
        }

        outer:
        for _, defaultRole := range schema.DefaultRoles {
            for _, role := range schema.Roles {
                if role.Name == defaultRole.Name {
                    continue outer;
                }
            }

            return fmt.Errorf(
				"Invalid default role '%s' in '%s' schema: there are no such role in this schema",
                defaultRole.Name,
                schema.ID,
            )
        }
    }

    if err := validateDefaultRoles(host.GlobalRoles, host.DefaultRoles); err != nil {
        return err
    }

    Debug.Log("[ RBAC ] Validating host: OK")

    return nil
}

