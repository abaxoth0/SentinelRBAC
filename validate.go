package rbac

import (
	"errors"
	"fmt"
)

func validateDefaultRoles(roles []Role, defaultRoles []Role) error {
	roleMap := make(map[string]bool)
	for _, role := range roles {
		roleMap[role.Name] = true
	}

	for _, defaultRole := range defaultRoles {
		if !roleMap[defaultRole.Name] {
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

	for ruleName, rule := range schema.ActionGatePolicy.rules {
		if err := rule.Effect.Validate(); err != nil {
			return fmt.Errorf("Invalid Action Gate Policy rule %s in the %s schema - %s", ruleName, schema.ID, err.Error())
		}

		if !entityMap[rule.Entity.name] {
			return fmt.Errorf(
				"Invalid Action Gate Policy rule %s - Entity %s doesn't exist in the %s schema",
				ruleName, rule.Entity.name, schema.ID,
			)
		}

		if !resourceMap[rule.Resource.name] {
			return fmt.Errorf(
				"Invalid Action Gate Policy rule %s - resource %s doesn't exist in the %s schema",
				ruleName, rule.Resource.name, schema.ID,
			)
		}

		for _, ruleRole := range rule.Roles {
			if !roleMap[ruleRole.Name] {
				return fmt.Errorf(
					"Invalid Action Gate Policy rule %s - Role %s doesn't exist in the %s schema",
					ruleName, ruleRole.Name, schema.ID,
				)
			}
		}

		if !rule.Entity.HasAction(rule.Action) {
			return fmt.Errorf(
				"Invalid Action Gate Policy rule %s - Action %s doesn't exist in the %s schema",
				ruleName, rule.Action, schema.ID,
			)
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

		// Create a map for O(1) lookups
		roleMap := make(map[string]bool)
		for _, role := range schema.Roles {
			roleMap[role.Name] = true
		}

		for _, defaultRole := range schema.DefaultRoles {
			if !roleMap[defaultRole.Name] {
				return fmt.Errorf(
					"Invalid default role '%s' in '%s' schema: there are no such role in this schema",
					defaultRole.Name,
					schema.ID,
				)
			}
		}
	}

	if err := validateDefaultRoles(host.GlobalRoles, host.DefaultRoles); err != nil {
		return err
	}

	Debug.Log("Validating host: OK")

	return nil
}
