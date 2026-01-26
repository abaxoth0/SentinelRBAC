package rbac

import (
	"testing"
)

func TestHost_GetSchema(t *testing.T) {
	// Create a host with multiple schemas
	schema1 := Schema{ID: "schema1"}
	schema2 := Schema{ID: "schema2"}
	schema3 := Schema{ID: "schema3"}

	host := Host{
		Schemas: []Schema{schema1, schema2, schema3},
	}

	// Test getting a schema
	got, err := host.GetSchema("schema2")
	if err != nil {
		t.Fatalf("GetSchema returned error: %v", err)
	}

	if got.ID != "schema2" {
		t.Errorf("Expected schema ID 'schema2', got '%s'", got.ID)
	}

	// CRITICAL: Verify that the returned pointer points to the actual schema in the host
	// Modify the returned schema and verify it affects the host's schema
	got.ID = "modified"
	if host.Schemas[1].ID != "modified" {
		t.Errorf("Returned pointer does not point to actual schema in host! Expected 'modified', got '%s'", host.Schemas[1].ID)
	}

	// Test getting non-existent schema
	_, err = host.GetSchema("nonexistent")
	if err == nil {
		t.Error("Expected error for non-existent schema, got nil")
	}

	// Test empty ID
	_, err = host.GetSchema("")
	if err == nil {
		t.Error("Expected error for empty ID, got nil")
	}

	// Test nil host
	var nilHost *Host
	_, err = nilHost.GetSchema("schema1")
	if err == nil {
		t.Error("Expected error for nil host, got nil")
	}
}

