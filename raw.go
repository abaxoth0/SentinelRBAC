package rbac

import (
	"fmt"
)

// TODO add partial loading (to be able for example to init all actions in code, but load AGP from config)

// "raw" structs are designed to be used by host and schema to be able to be initialized from files.
// They are more user-friendly, but also more "heavy".
//
// So for example - rawPermissions is just a struct which consists of flags,
// instead original Permissions is bitmask.
// Of course rawPermissions are more convenient and readable, but also slower.
// For example:
// For authz using Permissions used bitwise operations which are extremely fast,
// but using rawPermissions the only way is to check all flag one-by-one in 'if' statements.

type rawPermissions struct {
	Create     bool `json:"create"`
	SelfCreate bool `json:"self-create"`
	Read       bool `json:"read"`
	SelfRead   bool `json:"self-read"`
	Update     bool `json:"update"`
	SelfUpdate bool `json:"self-update"`
	Delete     bool `json:"delete"`
	SelfDelete bool `json:"self-delete"`
}

func (r rawPermissions) ToBitmask() Permissions {
	var permissions Permissions

	if r.Create {
		permissions |= CreatePermission
	}
	if r.SelfCreate {
		permissions |= SelfCreatePermission
	}
	if r.Read {
		permissions |= ReadPermission
	}
	if r.SelfRead {
		permissions |= SelfReadPermission
	}
	if r.Update {
		permissions |= UpdatePermission
	}
	if r.SelfUpdate {
		permissions |= SelfUpdatePermission
	}
	if r.Delete {
		permissions |= DeletePermission
	}
	if r.SelfDelete {
		permissions |= SelfDeletePermission
	}

	return permissions
}

type rawRole struct {
	Name        string          `json:"name"`
	Permissions *rawPermissions `json:"permissions"`
}

type rawAction struct {
	Name                string          `json:"name"`
	RequiredPermissions *rawPermissions `json:"required-permissions"`
}

type rawActionGateRules struct {
	// Entities
	For []string `json:"for"`
	// Roles
	Having []string `json:"having,omitempty"`
	// Effect
	Apply string `json:"apply"`
	// Actions
	Doing []string `json:"doing"`
	// Resource
	On string `json:"on"`
}

type rawEntity struct {
	Name    string       `json:"name"`
	Actions []*rawAction `json:"actions"`
}

type rawSchema struct {
	ID                string                `json:"id"`
	DefaultRolesNames []string              `json:"default-roles,omitempty"`
	Roles             []*rawRole            `json:"roles,omitempty"`
	Entities          []*rawEntity          `json:"entities,omitempty"`
	Resources         []string              `json:"resources,omitempty"`
	ActionGatePolicy  []*rawActionGateRules `json:"action-gate-policy,omitempty"`
}

func normalizeRoles(rawRoles []*rawRole) []Role {
	roles := make([]Role, len(rawRoles))

	for i, rawRole := range rawRoles {
		roles[i] = NewRole(
			rawRole.Name,
			rawRole.Permissions.ToBitmask(),
		)
	}

	return roles
}

func normalizeDefaultRoles(roles []Role, defaultRolesNames []string) ([]Role, error) {
	roleMap := buildRoleMap(roles)
	return rolesByNames(roleMap, defaultRolesNames)
}

// Used to get slice of normalized elements using their raw representations.
func normalizeActionGatePolicy(
	schemaEntities []Entity,
	schemaRoles []Role,
	schemaResources []Resource,
	rawAgp []*rawActionGateRules,
) (ActionGatePolicy, error) {
	var zero ActionGatePolicy

	agp := NewActionGatePolicy()

	entityMap := make(map[string]Entity, len(schemaEntities))
	entityActions := make(map[string]map[string]Action, len(schemaEntities))
	for _, entity := range schemaEntities {
		entityMap[entity.name] = entity

		actionMap := make(map[string]Action, len(entity.actions))
		for action := range entity.actions {
			actionMap[action.String()] = action
		}
		entityActions[entity.name] = actionMap
	}

	resourceMap := make(map[string]Resource, len(schemaResources))
	for _, resource := range schemaResources {
		resourceMap[resource.name] = resource
	}

	roleMap := buildRoleMap(schemaRoles)

	for _, rawRule := range rawAgp {
		ruleResource, ok := resourceMap[rawRule.On]
		if !ok {
			return zero, fmt.Errorf("Resource %s doesn't exist in the schema resources", rawRule.On)
		}

		if rawRule.For == nil || len(rawRule.For) == 0 {
			return zero, fmt.Errorf("Rule missing entity(-s) for the %s resource", ruleResource.name)
		}

		if rawRule.Doing == nil || len(rawRule.Doing) == 0 {
			return zero, fmt.Errorf("Rule missing action(-s) for the %s resource", ruleResource.name)
		}

		var ruleRoles []Role
		if len(rawRule.Having) > 0 {
			roles, err := rolesByNames(roleMap, rawRule.Having)
			if err != nil {
				return zero, fmt.Errorf("Failed to get normalized roles - %s", err.Error())
			}
			ruleRoles = roles
		}

		for _, entityName := range rawRule.For {
			ruleEntity, ok := entityMap[entityName]
			if !ok {
				return zero, fmt.Errorf("Failed to get normalized entity - \"%s\" doesn't exist", entityName)
			}

			actionMap := entityActions[entityName]
			ruleActions := make([]Action, 0, len(rawRule.Doing))
			for _, actionName := range rawRule.Doing {
				action, ok := actionMap[actionName]
				if !ok {
					return zero, fmt.Errorf("Failed to get normalized action for the %s entity - \"%s\" doesn't exist", ruleEntity.name, actionName)
				}
				ruleActions = append(ruleActions, action)
			}

			for _, ruleAction := range ruleActions {
				err := agp.AddRule(&ActionGateRule{
					Entity:   ruleEntity,
					Effect:   ActionGateEffect(rawRule.Apply),
					Roles:    ruleRoles,
					Action:   ruleAction,
					Resource: ruleResource,
				})
				if err != nil {
					return zero, err
				}
			}
		}
	}

	return agp, nil
}

func normalizeEntities(rawEntities []*rawEntity) []Entity {
	entities := make([]Entity, 0, len(rawEntities))

	for _, rawEntity := range rawEntities {
		entity := NewEntity(rawEntity.Name)

		for _, rawAct := range rawEntity.Actions {
			entity.NewAction(rawAct.Name, rawAct.RequiredPermissions.ToBitmask())
		}

		entities = append(entities, entity)
	}

	return entities
}

func normalizeResources(rawResources []string) []Resource {
	resources := make([]Resource, 0, len(rawResources))

	for _, rawResource := range rawResources {
		resources = append(resources, Resource{
			name: rawResource,
		})
	}

	return resources
}

// Creates new Schema based on self.
func (s *rawSchema) Normalize() (Schema, error) {
	Debug.Log("Normalizing schema...")

	schema := Schema{}

	var err error

	schema.ID = s.ID
	schema.Roles = normalizeRoles(s.Roles)

	defaultRoles, err := normalizeDefaultRoles(schema.Roles, s.DefaultRolesNames)
	if err != nil {
		return Schema{}, err
	}

	schema.DefaultRoles = defaultRoles
	schema.Entities = normalizeEntities(s.Entities)
	schema.Resources = normalizeResources(s.Resources)

	agp, err := normalizeActionGatePolicy(
		schema.Entities,
		schema.Roles,
		schema.Resources,
		s.ActionGatePolicy,
	)
	if err != nil {
		return Schema{}, fmt.Errorf("Failed to normalize Action Gate Policy for the %s schema: %s", schema.ID, err.Error())
	}

	schema.ActionGatePolicy = agp

	Debug.Log("Normalizing schema: OK")

	return schema, nil
}

func (s *rawSchema) NormalizeAndValidate() (Schema, error) {
	var zero Schema

	schema, err := s.Normalize()
	if err != nil {
		return zero, err
	}

	if err := ValidateSchema(&schema); err != nil {
		return zero, err
	}

	return schema, nil
}

type rawHost struct {
	DefaultRolesNames []string     `json:"default-roles,omitempty"`
	GlobalRoles       []*rawRole   `json:"roles"`
	Schemas           []*rawSchema `json:"schemas"`
}

// Creates new Host based on self.
func (h *rawHost) Normalize() (Host, error) {
	var zero Host

	Debug.Log("Normalizing host...")

	host := Host{}

	host.Schemas = make([]Schema, len(h.Schemas))

	for i, rawSchema := range h.Schemas {
		schema, err := rawSchema.Normalize()
		if err != nil {
			return zero, err
		}
		host.Schemas[i] = schema
	}

	var err error

	host.GlobalRoles = normalizeRoles(h.GlobalRoles)
	host.DefaultRoles, err = normalizeDefaultRoles(host.GlobalRoles, h.DefaultRolesNames)
	if err != nil {
		return zero, err
	}

	Debug.Log("Normalizing host: OK")

	return host, nil
}

func (h rawHost) NormalizeAndValidate() (Host, error) {
	var zero Host

	host, err := h.Normalize()
	if err != nil {
		return zero, err
	}

	if err := ValidateHost(&host); err != nil {
		return zero, err
	}

	return host, nil
}
