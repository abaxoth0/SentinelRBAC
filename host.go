package rbac

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"slices"
)

type host struct {
	// Role wich will have all new users, must correspond with one of the default roles' name. (optional)
	OriginRoleName string    `json:"origing-role,omitempty"`
	DefaultRoles   []*Role   `json:"default-roles"`
	Schemas        []*Schema `json:"schemas"`
}

// Only one instance of host must exist at a time.
var Host *host

func GetSchema(ID string) (*Schema, *Error) {
	if Host == nil {
		return nil, NewError("RBAC schema is not defined")
	}

	if ID == "" {
		return nil, NewError("Missing schema id")
	}

	for _, schema := range Host.Schemas {
		if schema.ID == ID {
			return schema, nil
		}
	}

	return nil, NewError("Schema with id \"" + ID + "\" wasn't found")
}

// Reads the RBAC configuration file from the given path,
// parses it and sets the Schema variable to the parsed configuration.
// After loading, it checks the configuration for errors and returns an error if any were found.
// Also merges schema specific roles with permissions with the default roles' permissions.
func LoadHost(path string) error {
	log.Println("[ RBAC ] Loading configuration...")

	file, err := os.Open(path)

	if err != nil {
		if os.IsNotExist(err) {
			return errors.New("RBAC host configuration file wasn't found")
		}

		return err
	}

	// panic calls defered functions, so it will be called in any case
	defer func() {
		if err = file.Close(); err != nil {
			log.Println(err.Error())
			os.Exit(1)
		}
	}()

	buf, err := io.ReadAll(file)

	if err != nil {
		return err
	}

	Host = &host{}

	if err := json.NewDecoder(bytes.NewReader(buf)).Decode(Host); err != nil {
		return errors.New("[ RBAC ] Failed to parse RBAC host configuration file: " + err.Error())
	}

	log.Println("[ RBAC ] Loading host configuration: OK")

	log.Println("[ RBAC ] Checking host configuration...")

	if err = validateHost(Host); err != nil {
		return err
	}

	log.Println("[ RBAC ] Checking host configuration: OK")

	log.Println("[ RBAC ] Merging schemas permissions...")

	mergeSchemasPermissions(Host)

	log.Println("[ RBAC ] Merging schemas permissions: OK")

	return nil
}

func validateHost(host *host) error {
	if len(host.Schemas) == 0 {
		return errors.New("at least one schema must be defined")
	}

	isOriginRoleFound := false

	for _, defaultRole := range host.DefaultRoles {
		if defaultRole.Name == host.OriginRoleName {
			isOriginRoleFound = true
		}

		for _, permission := range defaultRole.Permissions {
			if !slices.Contains(permissions[:], permission) {
				err := fmt.Sprintf("invalid permission \"%s\" in default role: \"%s\"", string(permission), defaultRole.Name)
				return errors.New(err)
			}
		}
	}

	if host.OriginRoleName != "" && !isOriginRoleFound {
		err := fmt.Sprintf("invalid origing role \"%s\", it must be one of the default roles' names", host.OriginRoleName)
		return errors.New(err)
	}

	for _, schema := range host.Schemas {
		for _, serviceRole := range schema.Roles {
			for _, permission := range serviceRole.Permissions {
				if !slices.Contains(permissions[:], permission) {
					err := fmt.Sprintf("invalid permission \"%s\" in \"%s\" role: \"%s\"", string(permission), schema.Name, serviceRole.Name)
					return errors.New(err)
				}
			}
		}
	}

	return nil
}

// Merges permissions from schema specific roles with default roles.
// If schema has a role with the same name as default role, schema role overwrites default role.
func mergeSchemasPermissions(host *host) {
	for _, schema := range host.Schemas {
		var roles []*Role = []*Role{}

		for _, schemaRole := range schema.Roles {
			for _, defaultRole := range host.DefaultRoles {
				if schemaRole.Name == defaultRole.Name {
					roles = append(roles, schemaRole)
				} else {
					roles = append(roles, defaultRole)
				}
			}
		}

		if schema.Roles == nil {
			roles = host.DefaultRoles
		}

		schema.Roles = roles
	}
}
