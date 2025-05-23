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
    debugLog("[ RBAC ] Validating schema '"+schema.Name+"' ("+schema.ID+")...")

    if err := validateDefaultRoles(schema.Roles, schema.DefaultRoles); err != nil {
        return err
    }

    debugLog("[ RBAC ] Validating schema '"+schema.Name+"' ("+schema.ID+"): OK")

    return nil
}

func ValidateHost(host *Host) error {
	debugLog("[ RBAC ] Validating host...")

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
                "Invalid default role '%s' in schema '%s' (%s). It must be one of this schema's roles",
                defaultRole.Name,
                schema.Name,
                schema.ID,
            )
        }
    }

    if err := validateDefaultRoles(host.GlobalRoles, host.DefaultRoles); err != nil {
        return err
    }

    debugLog("[ RBAC ] Validating host: OK")

    return nil
}

