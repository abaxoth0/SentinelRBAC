package rbac

import (
	"encoding/json"
	"fmt"
	"os"
)

type agpFile struct {
	ActionGatePolicy []*rawActionGateRules `json:"action-gate-policy"`
}

// LoadActionGatePolicyFromFile loads an action gate policy from disk and binds it
// to the provided sets of entities, roles and resources. This allows projects that
// define their domain model in code to keep policy definitions in configuration files.
func LoadActionGatePolicyFromFile(
	path string,
	entities []Entity,
	roles []Role,
	resources []Resource,
) (ActionGatePolicy, error) {
	var zero ActionGatePolicy

	if len(entities) == 0 {
		return zero, fmt.Errorf("at least one entity must be provided to load an action gate policy")
	}
	if len(roles) == 0 {
		return zero, fmt.Errorf("at least one role must be provided to load an action gate policy")
	}
	if len(resources) == 0 {
		return zero, fmt.Errorf("at least one resource must be provided to load an action gate policy")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return zero, err
	}

	var payload agpFile
	if err := json.Unmarshal(data, &payload); err != nil {
		return zero, fmt.Errorf("failed to parse action gate policy file: %w", err)
	}

	if len(payload.ActionGatePolicy) == 0 {
		return zero, fmt.Errorf("action gate policy file doesn't contain any rules")
	}

	return normalizeActionGatePolicy(entities, roles, resources, payload.ActionGatePolicy)
}

// LoadActionGatePolicy loads the policy for an existing schema from disk.
func (s *Schema) LoadActionGatePolicy(path string) error {
	agp, err := LoadActionGatePolicyFromFile(path, s.Entities, s.Roles, s.Resources)
	if err != nil {
		return err
	}

	s.ActionGatePolicy = agp
	return nil
}

