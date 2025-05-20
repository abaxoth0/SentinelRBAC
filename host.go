package rbac

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// Host originaly desined for applications with microservice architectures.
//
// Host helps to define roles and schemas for each service in your app.
// You can also select several roles as default roles, all new users must have this roles.
type Host struct {
	// (Optional)
    //
    // Roles wich will have all new users, each default role must correspond with one of existing global roles.
    DefaultRoles []Role
    Roles        []Role
    Schemas      []Schema
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
            return &schema, nil
        }
    }

    return nil, NewError("Schema with id \"" + ID + "\" wasn't found")
}

func (h *Host) Validate() error {
	if len(h.Schemas) == 0 {
		return errors.New("At least one schema must be defined")
	}

    rolesAmount := len(h.Roles)

    for _, defaultRole := range h.DefaultRoles {
        for i, role := range h.Roles {
            if defaultRole.Name == role.Name {
                break
            }

            if i + 1 == rolesAmount {
                return fmt.Errorf(
                    "Invalid default role \"%s\", it must be one of the roles names",
                    defaultRole.Name,
                )
            }
        }
    }

    return nil
}

// Merges permissions from schema specific roles with global roles.
// If any schema have a role with the same name as one of the global roles, then for each that role
// permissions of the schemas specific roles will overwrite permissions of the global roles.
// Also adds in schemas all global roles that wasn't explicitly specified for them.
func (h *Host) MergeRoles() {
    schemas := make([]Schema, len(h.Schemas))

	for i, oldSchema := range h.Schemas {
        schema := oldSchema

        if oldSchema.Roles == nil || len(oldSchema.Roles) == 0 {
            schema.Roles = h.Roles
            schemas[i] = schema
            continue
        }

        roles := []Role{}

		for _, schemaRole := range schema.Roles {
			for _, role := range h.Roles {
				if schemaRole.Name == role.Name {
					roles = append(roles, schemaRole)
				} else {
					roles = append(roles, role)
				}
			}
		}

		schema.Roles = roles

        schemas[i] = schema
	}

    h.Schemas = schemas
}

// Reads the RBAC configuration file from the given path.
// After loading and normalizing, it validates the configuration and returns an error if any of them were detected.
// Also merges permissions of the schema specific roles with permissions of the global roles.
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
	debugLog("[ RBAC ] Merging permissions of global and schemas roles...")

	host.MergeRoles()

    debugLog("[ RBAC ] Merging permissions of global and schemas roles: OK")

	return *host, nil
}

