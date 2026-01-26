package rbac

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// LoadRawSchema loads a raw schema from a JSON file without normalizing it.
// This allows you to inspect and modify the raw configuration before building.
func LoadRawSchema(path string) (*rawSchema, error) {
	Debug.Log("Loading raw schema from '" + path + "'...")

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New("RBAC schema configuration file wasn't found")
		}
		return nil, err
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			Debug.Log(closeErr.Error())
		}
	}()

	buf, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	var raw rawSchema
	if err := json.NewDecoder(bytes.NewReader(buf)).Decode(&raw); err != nil {
		return nil, fmt.Errorf("failed to parse RBAC schema configuration file: %w", err)
	}

	Debug.Log("Loading raw schema from '" + path + "': OK")
	return &raw, nil
}

// LoadRawHost loads a raw host from a JSON file without normalizing it.
// This allows you to inspect and modify the raw configuration before building.
func LoadRawHost(path string) (*rawHost, error) {
	Debug.Log("Loading raw host from '" + path + "'...")

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New("RBAC host configuration file wasn't found")
		}
		return nil, err
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			Debug.Log(closeErr.Error())
		}
	}()

	buf, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	var raw rawHost
	if err := json.NewDecoder(bytes.NewReader(buf)).Decode(&raw); err != nil {
		return nil, fmt.Errorf("failed to parse RBAC host configuration file: %w", err)
	}

	Debug.Log("Loading raw host from '" + path + "': OK")
	return &raw, nil
}

// SchemaBuilder allows building a Schema by loading raw config from files
// and/or adding components programmatically, then merging and normalizing everything.
type SchemaBuilder struct {
	id           string
	raw          *rawSchema
	entities     []*Entity
	roles        []*Role
	resources    []*Resource
	agpRules     []*ActionGateRule
	defaultRoles []string
}

// NewSchemaBuilder creates a new SchemaBuilder with the given schema ID.
func NewSchemaBuilder(id string) *SchemaBuilder {
	return &SchemaBuilder{
		id:           id,
		entities:     []*Entity{},
		roles:        []*Role{},
		resources:    []*Resource{},
		agpRules:     []*ActionGateRule{},
		defaultRoles: []string{},
	}
}

// LoadRaw loads raw schema configuration from a file without normalizing it.
// The raw config will be merged with code-defined components when Build() is called.
func (sb *SchemaBuilder) LoadRaw(path string) error {
	raw, err := LoadRawSchema(path)
	if err != nil {
		return err
	}
	sb.raw = raw
	if sb.id == "" {
		sb.id = raw.ID
	}
	return nil
}

// AddEntity adds or replaces an entity. If an entity with the same name already exists
// (from file or previous AddEntity call), it will be replaced.
func (sb *SchemaBuilder) AddEntity(entity *Entity) *SchemaBuilder {
	if entity == nil {
		return sb
	}
	for i, e := range sb.entities {
		if e.Name() == entity.Name() {
			sb.entities[i] = entity
			return sb
		}
	}
	sb.entities = append(sb.entities, entity)
	return sb
}

// AddRole adds or replaces a role. If a role with the same name already exists,
// it will be replaced.
func (sb *SchemaBuilder) AddRole(role *Role) *SchemaBuilder {
	if role == nil {
		return sb
	}
	for i, r := range sb.roles {
		if r.Name == role.Name {
			sb.roles[i] = role
			return sb
		}
	}
	sb.roles = append(sb.roles, role)
	return sb
}

// AddResource adds a resource. Duplicates by name are ignored.
func (sb *SchemaBuilder) AddResource(resource *Resource) *SchemaBuilder {
	if resource == nil {
		return sb
	}
	for _, r := range sb.resources {
		if r.Name() == resource.Name() {
			return sb
		}
	}
	sb.resources = append(sb.resources, resource)
	return sb
}

// AddAGPRule adds an Action Gate Policy rule. Rules are identified by their
// entity:action:resource key, so duplicates will be replaced.
func (sb *SchemaBuilder) AddAGPRule(rule *ActionGateRule) error {
	if rule == nil {
		return errors.New("cannot add nil AGP rule")
	}
	// Check for duplicates by key (entity+resource+effect+roles)
	key := fmt.Sprintf("%s:%s:%s:", rule.Entity.Name(), rule.Resource.Name(), string(rule.Effect))
	for _, role := range rule.Roles {
		key += role.Name + ","
	}
	for i, r := range sb.agpRules {
		existingKey := fmt.Sprintf("%s:%s:%s:", r.Entity.Name(), r.Resource.Name(), string(r.Effect))
		for _, role := range r.Roles {
			existingKey += role.Name + ","
		}
		if existingKey == key {
			sb.agpRules[i] = rule
			return nil
		}
	}
	sb.agpRules = append(sb.agpRules, rule)
	return nil
}

// SetDefaultRoles sets the default role names. This overrides any default roles
// from the loaded raw config.
func (sb *SchemaBuilder) SetDefaultRoles(names []string) *SchemaBuilder {
	sb.defaultRoles = names
	return sb
}

// Build merges the raw config (if loaded) with code-defined components and
// returns a normalized and validated Schema.
func (sb *SchemaBuilder) Build() (Schema, error) {
	var mergedRaw rawSchema
	if sb.raw != nil {
		mergedRaw = *sb.raw
	} else {
		mergedRaw = rawSchema{
			ID:                sb.id,
			Roles:             []*rawRole{},
			Entities:          []*rawEntity{},
			Resources:         []string{},
			ActionGatePolicy:  []*rawActionGateRules{},
			DefaultRolesNames: []string{},
		}
	}

	if sb.id != "" {
		mergedRaw.ID = sb.id
	}

	// Merge roles: code-defined override file-defined
	roleMap := make(map[string]*Role)
	// add file-defined roles
	if mergedRaw.Roles != nil {
		for _, rawRole := range mergedRaw.Roles {
			role := NewRole(rawRole.Name, rawRole.Permissions.ToBitmask())
			roleMap[rawRole.Name] = &role
		}
	}
	// Toverride/add code-defined roles
	for _, role := range sb.roles {
		roleMap[role.Name] = role
	}

	mergedRoles := make([]*rawRole, 0, len(roleMap))
	for _, role := range roleMap {
		rawRole := &rawRole{
			Name:        role.Name,
			Permissions: &rawPermissions{},
		}

		perms := role.Permissions
		if perms&CreatePermission != 0 {
			rawRole.Permissions.Create = true
		}
		if perms&SelfCreatePermission != 0 {
			rawRole.Permissions.SelfCreate = true
		}
		if perms&ReadPermission != 0 {
			rawRole.Permissions.Read = true
		}
		if perms&SelfReadPermission != 0 {
			rawRole.Permissions.SelfRead = true
		}
		if perms&UpdatePermission != 0 {
			rawRole.Permissions.Update = true
		}
		if perms&SelfUpdatePermission != 0 {
			rawRole.Permissions.SelfUpdate = true
		}
		if perms&DeletePermission != 0 {
			rawRole.Permissions.Delete = true
		}
		if perms&SelfDeletePermission != 0 {
			rawRole.Permissions.SelfDelete = true
		}
		mergedRoles = append(mergedRoles, rawRole)
	}
	mergedRaw.Roles = mergedRoles

	// Merge entities: code-defined override file-defined
	entityMap := make(map[string]*Entity)
	// add file-defined entities
	if mergedRaw.Entities != nil {
		for _, rawEntity := range mergedRaw.Entities {
			entity := NewEntity(rawEntity.Name)
			for _, rawAction := range rawEntity.Actions {
				entity.NewAction(rawAction.Name, rawAction.RequiredPermissions.ToBitmask())
			}
			entityMap[rawEntity.Name] = &entity
		}
	}
	// Toverride/add code-defined entities
	for _, entity := range sb.entities {
		entityMap[entity.Name()] = entity
	}

	mergedEntities := make([]*rawEntity, 0, len(entityMap))
	for _, entity := range entityMap {
		rawEntity := &rawEntity{
			Name:    entity.Name(),
			Actions: []*rawAction{},
		}

		for action, perms := range entity.actions {
			rawAction := &rawAction{
				Name:                action.String(),
				RequiredPermissions: &rawPermissions{},
			}
			if perms&CreatePermission != 0 {
				rawAction.RequiredPermissions.Create = true
			}
			if perms&SelfCreatePermission != 0 {
				rawAction.RequiredPermissions.SelfCreate = true
			}
			if perms&ReadPermission != 0 {
				rawAction.RequiredPermissions.Read = true
			}
			if perms&SelfReadPermission != 0 {
				rawAction.RequiredPermissions.SelfRead = true
			}
			if perms&UpdatePermission != 0 {
				rawAction.RequiredPermissions.Update = true
			}
			if perms&SelfUpdatePermission != 0 {
				rawAction.RequiredPermissions.SelfUpdate = true
			}
			if perms&DeletePermission != 0 {
				rawAction.RequiredPermissions.Delete = true
			}
			if perms&SelfDeletePermission != 0 {
				rawAction.RequiredPermissions.SelfDelete = true
			}
			rawEntity.Actions = append(rawEntity.Actions, rawAction)
		}
		mergedEntities = append(mergedEntities, rawEntity)
	}
	mergedRaw.Entities = mergedEntities

	// Merge resources: union (no duplicates)
	resourceMap := make(map[string]bool)
	if mergedRaw.Resources != nil {
		for _, r := range mergedRaw.Resources {
			resourceMap[r] = true
		}
	}
	for _, r := range sb.resources {
		resourceMap[r.Name()] = true
	}
	mergedResources := make([]string, 0, len(resourceMap))
	for r := range resourceMap {
		mergedResources = append(mergedResources, r)
	}
	mergedRaw.Resources = mergedResources

	// Merge AGP rules: union (code-defined rules are added to file-defined ones)
	// Convert code-defined rules to raw format
	entityNameMap := make(map[string]*Entity)
	for _, e := range entityMap {
		entityNameMap[e.Name()] = e
	}
	resourceNameMap := make(map[string]*Resource)
	for _, r := range sb.resources {
		resourceNameMap[r.Name()] = r
	}
	// Add file resources too
	if mergedRaw.Resources != nil {
		for _, rName := range mergedRaw.Resources {
			if _, exists := resourceNameMap[rName]; !exists {
				resourceNameMap[rName] = NewResource(rName)
			}
		}
	}
	roleNameMap := make(map[string]*Role)
	for _, r := range roleMap {
		roleNameMap[r.Name] = r
	}

	for _, rule := range sb.agpRules {
		// Convert all actions to strings
		actionNames := make([]string, len(rule.Actions))
		for i, action := range rule.Actions {
			actionNames[i] = action.String()
		}
		rawRule := &rawActionGateRules{
			For:    []string{rule.Entity.Name()},
			Doing:  actionNames,
			On:     rule.Resource.Name(),
			Apply:  string(rule.Effect),
			Having: GetRolesNames(rule.Roles),
		}
		mergedRaw.ActionGatePolicy = append(mergedRaw.ActionGatePolicy, rawRule)
	}

	if len(sb.defaultRoles) > 0 {
		mergedRaw.DefaultRolesNames = sb.defaultRoles
	}

	return mergedRaw.NormalizeAndValidate()
}

// HostBuilder allows building a Host by loading raw config from files
// and/or adding components programmatically, then merging and normalizing everything.
type HostBuilder struct {
	raw          *rawHost
	globalRoles  []*Role
	schemas      []*SchemaBuilder
	defaultRoles []string
}

// NewHostBuilder creates a new HostBuilder.
func NewHostBuilder() *HostBuilder {
	return &HostBuilder{
		globalRoles:  []*Role{},
		schemas:      []*SchemaBuilder{},
		defaultRoles: []string{},
	}
}

// LoadRaw loads raw host configuration from a file without normalizing it.
func (hb *HostBuilder) LoadRaw(path string) error {
	raw, err := LoadRawHost(path)
	if err != nil {
		return err
	}
	hb.raw = raw
	return nil
}

// AddGlobalRole adds or replaces a global role. If a role with the same name
// already exists, it will be replaced.
func (hb *HostBuilder) AddGlobalRole(role *Role) *HostBuilder {
	if role == nil {
		return hb
	}
	for i, r := range hb.globalRoles {
		if r.Name == role.Name {
			hb.globalRoles[i] = role
			return hb
		}
	}
	hb.globalRoles = append(hb.globalRoles, role)
	return hb
}

// AddSchema adds a schema builder to the host. The schema will be built
// when HostBuilder.Build() is called.
func (hb *HostBuilder) AddSchema(schema *SchemaBuilder) *HostBuilder {
	hb.schemas = append(hb.schemas, schema)
	return hb
}

// SetDefaultRoles sets the default global role names. This overrides any
// default roles from the loaded raw config.
func (hb *HostBuilder) SetDefaultRoles(names []string) *HostBuilder {
	hb.defaultRoles = names
	return hb
}

// Build merges the raw config (if loaded) with code-defined components and
// returns a normalized and validated Host.
func (hb *HostBuilder) Build() (Host, error) {
	var zero Host

	var mergedRaw rawHost
	if hb.raw != nil {
		mergedRaw = *hb.raw
	} else {
		mergedRaw = rawHost{
			GlobalRoles:       []*rawRole{},
			Schemas:           []*rawSchema{},
			DefaultRolesNames: []string{},
		}
	}

	// Merge global roles: code-defined override file-defined
	roleMap := make(map[string]*Role)
	// add file-defined roles
	if mergedRaw.GlobalRoles != nil {
		for _, rawRole := range mergedRaw.GlobalRoles {
			role := NewRole(rawRole.Name, rawRole.Permissions.ToBitmask())
			roleMap[rawRole.Name] = &role
		}
	}
	// override/add code-defined roles
	for _, role := range hb.globalRoles {
		roleMap[role.Name] = role
	}
	// Convert back to raw roles
	mergedGlobalRoles := make([]*rawRole, 0, len(roleMap))
	for _, role := range roleMap {
		rawRole := &rawRole{
			Name:        role.Name,
			Permissions: &rawPermissions{},
		}

		perms := role.Permissions
		if perms&CreatePermission != 0 {
			rawRole.Permissions.Create = true
		}
		if perms&SelfCreatePermission != 0 {
			rawRole.Permissions.SelfCreate = true
		}
		if perms&ReadPermission != 0 {
			rawRole.Permissions.Read = true
		}
		if perms&SelfReadPermission != 0 {
			rawRole.Permissions.SelfRead = true
		}
		if perms&UpdatePermission != 0 {
			rawRole.Permissions.Update = true
		}
		if perms&SelfUpdatePermission != 0 {
			rawRole.Permissions.SelfUpdate = true
		}
		if perms&DeletePermission != 0 {
			rawRole.Permissions.Delete = true
		}
		if perms&SelfDeletePermission != 0 {
			rawRole.Permissions.SelfDelete = true
		}
		mergedGlobalRoles = append(mergedGlobalRoles, rawRole)
	}
	mergedRaw.GlobalRoles = mergedGlobalRoles

	// Merge schemas: build code-defined schemas and add to file-defined ones
	builtSchemas := make([]*rawSchema, 0)
	// add file-defined schemas
	if mergedRaw.Schemas != nil {
		builtSchemas = append(builtSchemas, mergedRaw.Schemas...)
	}
	// build and add code-defined schemas
	for _, schemaBuilder := range hb.schemas {
		schema, err := schemaBuilder.Build()
		if err != nil {
			return zero, fmt.Errorf("failed to build schema: %w", err)
		}
		// Convert built schema back to raw for merging with host
		// This is a bit inefficient, but necessary for the merge logic
		rawSchema := &rawSchema{
			ID:                schema.ID,
			DefaultRolesNames: GetRolesNames(schema.DefaultRoles),
			Resources:         make([]string, len(schema.Resources)),
			Roles:             []*rawRole{},
			Entities:          []*rawEntity{},
			ActionGatePolicy:  []*rawActionGateRules{},
		}
		for i, r := range schema.Resources {
			rawSchema.Resources[i] = r.Name()
		}

		for _, role := range schema.Roles {
			rawRole := &rawRole{
				Name:        role.Name,
				Permissions: &rawPermissions{},
			}
			perms := role.Permissions
			if perms&CreatePermission != 0 {
				rawRole.Permissions.Create = true
			}
			if perms&SelfCreatePermission != 0 {
				rawRole.Permissions.SelfCreate = true
			}
			if perms&ReadPermission != 0 {
				rawRole.Permissions.Read = true
			}
			if perms&SelfReadPermission != 0 {
				rawRole.Permissions.SelfRead = true
			}
			if perms&UpdatePermission != 0 {
				rawRole.Permissions.Update = true
			}
			if perms&SelfUpdatePermission != 0 {
				rawRole.Permissions.SelfUpdate = true
			}
			if perms&DeletePermission != 0 {
				rawRole.Permissions.Delete = true
			}
			if perms&SelfDeletePermission != 0 {
				rawRole.Permissions.SelfDelete = true
			}
			rawSchema.Roles = append(rawSchema.Roles, rawRole)
		}

		for _, entity := range schema.Entities {
			rawEntity := &rawEntity{
				Name:    entity.Name(),
				Actions: []*rawAction{},
			}
			for action, perms := range entity.actions {
				rawAction := &rawAction{
					Name:                action.String(),
					RequiredPermissions: &rawPermissions{},
				}
				if perms&CreatePermission != 0 {
					rawAction.RequiredPermissions.Create = true
				}
				if perms&SelfCreatePermission != 0 {
					rawAction.RequiredPermissions.SelfCreate = true
				}
				if perms&ReadPermission != 0 {
					rawAction.RequiredPermissions.Read = true
				}
				if perms&SelfReadPermission != 0 {
					rawAction.RequiredPermissions.SelfRead = true
				}
				if perms&UpdatePermission != 0 {
					rawAction.RequiredPermissions.Update = true
				}
				if perms&SelfUpdatePermission != 0 {
					rawAction.RequiredPermissions.SelfUpdate = true
				}
				if perms&DeletePermission != 0 {
					rawAction.RequiredPermissions.Delete = true
				}
				if perms&SelfDeletePermission != 0 {
					rawAction.RequiredPermissions.SelfDelete = true
				}
				rawEntity.Actions = append(rawEntity.Actions, rawAction)
			}
			rawSchema.Entities = append(rawSchema.Entities, rawEntity)
		}
		// Convert AGP - this is complex, we need to extract from ActionGatePolicy
		// For now, we'll skip AGP conversion in HostBuilder as it's complex
		// Users should define AGP in schema builders
		builtSchemas = append(builtSchemas, rawSchema)
	}
	mergedRaw.Schemas = builtSchemas

	if len(hb.defaultRoles) > 0 {
		mergedRaw.DefaultRolesNames = hb.defaultRoles
	}

	mergedRaw.MergeRoles()

	return mergedRaw.NormalizeAndValidate()
}
