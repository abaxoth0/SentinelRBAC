package rbac

import (
	"os"
	"testing"
)

func TestSchemaBuilder_CodeOnly(t *testing.T) {
	// Test building a schema entirely from code
	builder := NewSchemaBuilder("test-schema")

	user := NewEntity("user")
	user.NewAction("read", ReadPermission)
	user.NewAction("write", CreatePermission|UpdatePermission)

	adminRole := NewRole("admin", ReadPermission|CreatePermission|UpdatePermission|DeletePermission)
	userRole := NewRole("user", ReadPermission)

	cache := NewResource("cache")

	builder.
		AddEntity(&user).
		AddRole(&adminRole).
		AddRole(&userRole).
		AddResource(cache).
		SetDefaultRoles([]string{"user"})

	schema, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if schema.ID != "test-schema" {
		t.Errorf("Expected ID 'test-schema', got '%s'", schema.ID)
	}

	if len(schema.Entities) != 1 {
		t.Errorf("Expected 1 entity, got %d", len(schema.Entities))
	}

	if len(schema.Roles) != 2 {
		t.Errorf("Expected 2 roles, got %d", len(schema.Roles))
	}

	if len(schema.Resources) != 1 {
		t.Errorf("Expected 1 resource, got %d", len(schema.Resources))
	}

	if len(schema.DefaultRoles) != 1 {
		t.Errorf("Expected 1 default role, got %d", len(schema.DefaultRoles))
	}

	if schema.DefaultRoles[0].Name != "user" {
		t.Errorf("Expected default role 'user', got '%s'", schema.DefaultRoles[0].Name)
	}
}

func TestSchemaBuilder_LoadRaw(t *testing.T) {
	// Create a temporary schema file
	config := `{
		"id": "file-schema",
		"roles": [
			{
				"name": "admin",
				"permissions": {
					"read": true,
					"create": true
				}
			}
		],
		"entities": [
			{
				"name": "user",
				"actions": [
					{
						"name": "read",
						"required-permissions": {
							"read": true
						}
					}
				]
			}
		],
		"resources": ["cache"],
		"default-roles": ["admin"]
	}`

	tmpfile, err := os.CreateTemp("", "schema-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.WriteString(config); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}
	tmpfile.Close()

	// Test loading raw and building
	builder := NewSchemaBuilder("")
	err = builder.LoadRaw(tmpfile.Name())
	if err != nil {
		t.Fatalf("LoadRaw failed: %v", err)
	}

	schema, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if schema.ID != "file-schema" {
		t.Errorf("Expected ID 'file-schema', got '%s'", schema.ID)
	}

	if len(schema.Roles) != 1 {
		t.Errorf("Expected 1 role, got %d", len(schema.Roles))
	}

	if len(schema.Entities) != 1 {
		t.Errorf("Expected 1 entity, got %d", len(schema.Entities))
	}
}

func TestSchemaBuilder_Merge(t *testing.T) {
	// Create a temporary schema file
	config := `{
		"id": "merge-schema",
		"roles": [
			{
				"name": "file-role",
				"permissions": {
					"read": true
				}
			}
		],
		"entities": [
			{
				"name": "file-entity",
				"actions": [
					{
						"name": "read",
						"required-permissions": {
							"read": true
						}
					}
				]
			}
		],
		"resources": ["file-resource"]
	}`

	tmpfile, err := os.CreateTemp("", "schema-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.WriteString(config); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}
	tmpfile.Close()

	// Load raw and add code-defined components
	builder := NewSchemaBuilder("merge-schema")
	err = builder.LoadRaw(tmpfile.Name())
	if err != nil {
		t.Fatalf("LoadRaw failed: %v", err)
	}

	// Add a role that overrides file role
	codeRole := NewRole("file-role", ReadPermission|CreatePermission) // Override
	newRole := NewRole("code-role", UpdatePermission)                 // New

	// Add an entity that overrides file entity
	codeEntity := NewEntity("file-entity") // Override
	codeEntity.NewAction("read", ReadPermission)
	codeEntity.NewAction("write", CreatePermission) // New action

	newEntity := NewEntity("code-entity") // New
	newEntity.NewAction("delete", DeletePermission)

	// Add resources
	codeResource := NewResource("code-resource")

	builder.
		AddRole(&codeRole).
		AddRole(&newRole).
		AddEntity(&codeEntity).
		AddEntity(&newEntity).
		AddResource(codeResource).
		SetDefaultRoles([]string{"file-role"})

	schema, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Verify merge: file-role should be overridden (have CreatePermission now)
	foundFileRole := false
	for _, role := range schema.Roles {
		if role.Name == "file-role" {
			foundFileRole = true
			if role.Permissions&CreatePermission == 0 {
				t.Error("file-role should have CreatePermission after override")
			}
		}
	}
	if !foundFileRole {
		t.Error("file-role should exist after merge")
	}

	// Verify code-role exists
	foundCodeRole := false
	for _, role := range schema.Roles {
		if role.Name == "code-role" {
			foundCodeRole = true
		}
	}
	if !foundCodeRole {
		t.Error("code-role should exist after merge")
	}

	// Verify resources are merged (union)
	foundFileResource := false
	foundCodeResource := false
	for _, resource := range schema.Resources {
		if resource.Name() == "file-resource" {
			foundFileResource = true
		}
		if resource.Name() == "code-resource" {
			foundCodeResource = true
		}
	}
	if !foundFileResource {
		t.Error("file-resource should exist after merge")
	}
	if !foundCodeResource {
		t.Error("code-resource should exist after merge")
	}

	// Verify entities are merged
	foundFileEntity := false
	foundCodeEntity := false
	for _, entity := range schema.Entities {
		if entity.Name() == "file-entity" {
			foundFileEntity = true
			// Should have both read and write actions
			if !entity.HasAction(Action("read")) {
				t.Error("file-entity should have 'read' action")
			}
			if !entity.HasAction(Action("write")) {
				t.Error("file-entity should have 'write' action after override")
			}
		}
		if entity.Name() == "code-entity" {
			foundCodeEntity = true
		}
	}
	if !foundFileEntity {
		t.Error("file-entity should exist after merge")
	}
	if !foundCodeEntity {
		t.Error("code-entity should exist after merge")
	}
}

func TestSchemaBuilder_AddAGPRule(t *testing.T) {
	builder := NewSchemaBuilder("agp-schema")

	user := NewEntity("user")
	readAction, _ := user.NewAction("read", ReadPermission)
	cache := NewResource("cache")
	adminRole := NewRole("admin", ReadPermission)

	builder.AddEntity(&user).AddRole(&adminRole).AddResource(cache)

	ctx := NewAuthorizationContext(&user, readAction, cache)
	rule := NewActionGateRule(&ctx, AllowActionGateEffect, []Role{adminRole})

	err := builder.AddAGPRule(rule)
	if err != nil {
		t.Fatalf("AddAGPRule failed: %v", err)
	}

	schema, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Verify AGP rule exists
	testCtx := NewAuthorizationContext(&user, readAction, cache)
	_, ok := schema.ActionGatePolicy.GetRule(&testCtx)
	if !ok {
		t.Error("AGP rule should exist after build")
	}
}

func TestHostBuilder_CodeOnly(t *testing.T) {
	builder := NewHostBuilder()

	adminRole := NewRole("admin", ReadPermission|CreatePermission)
	userRole := NewRole("user", ReadPermission)

	schemaBuilder := NewSchemaBuilder("test-schema")
	user := NewEntity("user")
	user.NewAction("read", ReadPermission)
	schemaBuilder.AddEntity(&user).AddRole(&userRole)

	builder.
		AddGlobalRole(&adminRole).
		AddGlobalRole(&userRole).
		AddSchema(schemaBuilder).
		SetDefaultRoles([]string{"user"})

	host, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if len(host.GlobalRoles) != 2 {
		t.Errorf("Expected 2 global roles, got %d", len(host.GlobalRoles))
	}

	if len(host.Schemas) != 1 {
		t.Errorf("Expected 1 schema, got %d", len(host.Schemas))
	}

	if len(host.DefaultRoles) != 1 {
		t.Errorf("Expected 1 default role, got %d", len(host.DefaultRoles))
	}
}
