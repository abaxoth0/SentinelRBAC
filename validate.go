package rbac

import (
	"errors"
	"fmt"
	"slices"
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
            "Invalid role '%s'. This role doesn't exist in Schema roles",
            defaultRole.Name,
        )
    }

    return nil
}

func validateAGP(schema *Schema) error {
	for ruleName, rule := range schema.ActionGatePolicy.rules {
		if err := rule.Effect.Validate(); err != nil {
			return fmt.Errorf("Invalid Action Gate Policy rule %s in the %s schema - %s", ruleName, schema.ID, err.Error())
		}

		if !slices.ContainsFunc(schema.Entities, func(v Entity) bool {
			return v.name == rule.Entity.name
		}) {
			return fmt.Errorf(
				"Invalid Action Gate Policy rule %s - Entity %s doesn't exist in the %s schema",
				ruleName, rule.Entity.name, schema.ID,
			)
		}

		if !slices.Contains(schema.Resources, rule.Resource) {
			return fmt.Errorf(
				"Invalid Action Gate Policy rule %s - resource %s doesn't exist in the %s schema",
				ruleName, rule.Resource.name, schema.ID,
			)
		}

		for _, ruleRole := range rule.Roles {
			if !slices.Contains(schema.Roles, ruleRole) {
				return fmt.Errorf(
					"Invalid Action Gate Policy rule %s - Role %s doesn't exist in the %s schema",
					ruleName, ruleRole.Name, schema.ID,
				)
			}
		}

		actions := []Action{}
		for _, entity := range schema.Entities {
			for action := range entity.actions {
				actions = append(actions, action)
			}
		}

		if !slices.Contains(actions, rule.Action) {
			return fmt.Errorf(
				"Invalid Action Gate Policy rule %s - Action %s doesn't exist in the %s schema",
				ruleName, rule.Action, schema.ID,
			)
		}
	}

	return nil
}

func ValidateSchema(schema *Schema) error {
    Debug.Log("Validating schema '"+schema.ID+"' ("+schema.ID+")...")

    if err := validateDefaultRoles(schema.Roles, schema.DefaultRoles); err != nil {
        return err
    }
	if err := validateAGP(schema); err != nil {
		return err
	}

    Debug.Log("Validating schema '"+schema.ID+"' ("+schema.ID+"): OK")

    return nil
}

func ValidateHost(host *Host) error {
	Debug.Log("Validating host...")

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

    Debug.Log("Validating host: OK")

    return nil
}

