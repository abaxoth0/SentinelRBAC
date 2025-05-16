package rbac

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
)

// Host originaly desined for applications with microservice architectures.
//
// Host helps to define roles and schemas for each service in your app.
// You can also select several roles as default roles, all new users must have this roles.
type Host struct {
	// (Optional)
    //
    // Roles wich will have all new users, each default role must correspond with one of existing roles name.
    DefaultRolesNames []string
    Roles             []*Role
    Schemas           []*Schema
}

func (h *Host) GetSchema(ID string) (*Schema, *Error) {
    if h == nil {
        return nil, NewError("RBAC schema is not defined")
    }

    if ID == "" {
        return nil, NewError("Missing schema id")
    }

    for _, schema := range h.Schemas {
        if schema.ID == ID {
            return schema, nil
        }
    }

    return nil, NewError("Schema with id \"" + ID + "\" wasn't found")
}

func (h *Host) Validate() error {
	if len(h.Schemas) == 0 {
		return errors.New("At least one schema must be defined")
	}

	for _, role := range h.Roles {
        if slices.Contains(h.DefaultRolesNames, role.Name) {
            return nil
        }
	}

    return fmt.Errorf(
        "Invalid default role \"%s\", it must be one of the roles names",
        h.DefaultRolesNames,
    )
}

// Merges permissions from schema specific roles with default roles.
// If schema has a role with the same name as default role, schema role overwrites default role.
func (h *Host) MergePermissions() {
	for _, schema := range h.Schemas {
		roles := []*Role{}

		for _, schemaRole := range schema.Roles {
			for _, defaultRole := range h.Roles {
				if schemaRole.Name == defaultRole.Name {
					roles = append(roles, schemaRole)
				} else {
					roles = append(roles, defaultRole)
				}
			}
		}

		if schema.Roles == nil {
			roles = h.Roles
		}

		schema.Roles = roles
	}
}

// Reads the RBAC configuration file from the given path,
// parses it and sets the Schema variable to the parsed configuration.
// After loading, it checks the configuration for errors and returns an error if any were found.
// Also merges schema specific roles with permissions with the default roles' permissions.
func LoadHost(path string) (Host, error) {
    var zero Host

	debugLog("[ RBAC ] Loading configuration...")

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return zero, errors.New("RBAC host configuration file wasn't found")
		}

		return zero, err
	}
	defer func() {
		if err = file.Close(); err != nil {
			debugLog(err.Error())
			os.Exit(1)
		}
	}()

	buf, err := io.ReadAll(file)
	if err != nil {
		return zero, err
	}

	raw := &rawHost{}
	if err := json.NewDecoder(bytes.NewReader(buf)).Decode(raw); err != nil {
		return zero, errors.New("Failed to parse RBAC host configuration file: " + err.Error())
	}

    debugLog("[ RBAC ] Loading host configuration: OK")
    debugLog("[ RBAC ] Normalizing host configuration...")

    host := raw.Normalize()

    debugLog("[ RBAC ] Normalizing host configuration: OK")
	debugLog("[ RBAC ] Validating host configuration...")

	if err = host.Validate(); err != nil {
		return zero, err
	}

	debugLog("[ RBAC ] Validating host configuration: OK")
	debugLog("[ RBAC ] Merging schemas permissions...")

	host.MergePermissions()

	debugLog("[ RBAC ] Merging schemas permissions: OK")

	return host, nil
}

