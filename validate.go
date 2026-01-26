package rbac

import (
	"errors"
	"fmt"
)

func validateDefaultRoles(roles []*Role, defaultRoles []*Role) error {
	roleMap := buildRoleMap(roles)

	for _, defaultRole := range defaultRoles {
		if _, exists := roleMap[defaultRole.Name]; !exists {
			return fmt.Errorf(
				"Invalid role '%s'. This role doesn't exist in Schema roles",
				defaultRole.Name,
			)
		}
	}

	return nil
}

func validateAGP(schema *Schema) error {
	// Create lookup maps for O(1) validation
	entityMap := make(map[string]bool)
	for _, entity := range schema.Entities {
		entityMap[entity.name] = true
	}

	resourceMap := make(map[string]bool)
	for _, resource := range schema.Resources {
		resourceMap[resource.name] = true
	}

	roleMap := make(map[string]bool)
	for _, role := range schema.Roles {
		roleMap[role.Name] = true
	}

	// Validate all rules in the policy by iterating through the index
	for _, rules := range schema.ActionGatePolicy.index {
		for _, rule := range rules {
			if err := rule.Effect.Validate(); err != nil {
				return fmt.Errorf("Invalid Action Gate Policy rule in the %s schema - %s", schema.ID, err.Error())
			}

			if rule.Entity == nil {
				return fmt.Errorf("Invalid Action Gate Policy rule - Entity is nil in the %s schema", schema.ID)
			}
			if !entityMap[rule.Entity.name] {
				return fmt.Errorf(
					"Invalid Action Gate Policy rule - Entity %s doesn't exist in the %s schema",
					rule.Entity.name, schema.ID,
				)
			}

			if rule.Resource == nil {
				return fmt.Errorf("Invalid Action Gate Policy rule - Resource is nil in the %s schema", schema.ID)
			}
			if !resourceMap[rule.Resource.name] {
				return fmt.Errorf(
					"Invalid Action Gate Policy rule - resource %s doesn't exist in the %s schema",
					rule.Resource.name, schema.ID,
				)
			}

			for _, ruleRole := range rule.Roles {
				if ruleRole == nil {
					return fmt.Errorf("Invalid Action Gate Policy rule - Role is nil in the %s schema", schema.ID)
				}
				if !roleMap[ruleRole.Name] {
					return fmt.Errorf(
						"Invalid Action Gate Policy rule - Role %s doesn't exist in the %s schema",
						ruleRole.Name, schema.ID,
					)
				}
			}

			// Validate that all actions in the rule exist for the entity
			for _, action := range rule.Actions {
				if !rule.Entity.HasAction(action) {
					return fmt.Errorf(
						"Invalid Action Gate Policy rule - Action %s doesn't exist in the %s schema",
						action, schema.ID,
					)
				}
			}
		}
	}

	return nil
}

func ValidateSchema(schema *Schema) error {
	Debug.Log("Validating schema '" + schema.ID + "' (" + schema.ID + ")...")

	if err := validateDefaultRoles(schema.Roles, schema.DefaultRoles); err != nil {
		return err
	}
	if err := validateAGP(schema); err != nil {
		return err
	}

	Debug.Log("Validating schema '" + schema.ID + "' (" + schema.ID + "): OK")

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

		if err := validateDefaultRoles(schema.Roles, schema.DefaultRoles); err != nil {
			return err
		}
	}

	if err := validateDefaultRoles(host.GlobalRoles, host.DefaultRoles); err != nil {
		return err
	}

	Debug.Log("Validating host: OK")

	return nil
}
