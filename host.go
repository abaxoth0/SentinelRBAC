package rbac

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
)

type Host struct {
	// Role wich will have all new users, must correspond with one of the default roles' name. (optional)
	OriginRoleName string    `json:"origing-role,omitempty"`
	DefaultRoles   []*Role   `json:"default-roles"`
	Schemas        []*Schema `json:"schemas"`
}

func (host *Host) GetSchema(ID string) (*Schema, *Error) {
	if host == nil {
		return nil, NewError("RBAC schema is not defined")
	}

	if ID == "" {
		return nil, NewError("Missing schema id")
	}

	for _, schema := range host.Schemas {
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
func LoadHost(path string) (*Host, error) {
	log.Println("[ RBAC ] Loading configuration...")

	file, err := os.Open(path)

	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New("RBAC host configuration file wasn't found")
		}

		return nil, err
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
		return nil, err
	}

	host := &Host{}

	if err := json.NewDecoder(bytes.NewReader(buf)).Decode(host); err != nil {
		return nil, errors.New("[ RBAC ] Failed to parse RBAC host configuration file: " + err.Error())
	}

	log.Println("[ RBAC ] Loading host configuration: OK")

	log.Println("[ RBAC ] Checking host configuration...")

	if err = host.Validate(); err != nil {
		return nil, err
	}

	log.Println("[ RBAC ] Checking host configuration: OK")

	log.Println("[ RBAC ] Merging schemas permissions...")

	host.MergePermissions()

	log.Println("[ RBAC ] Merging schemas permissions: OK")

	return host, nil
}

func (host *Host) Validate() error {
	if len(host.Schemas) == 0 {
		return errors.New("at least one schema must be defined")
	}

	isOriginRoleFound := false

	for _, defaultRole := range host.DefaultRoles {
		if defaultRole.Name == host.OriginRoleName {
			isOriginRoleFound = true
		}
	}

	if host.OriginRoleName != "" && !isOriginRoleFound {
		err := fmt.Sprintf("invalid origing role \"%s\", it must be one of the default roles' names", host.OriginRoleName)
		return errors.New(err)
	}

	return nil
}

// Merges permissions from schema specific roles with default roles.
// If schema has a role with the same name as default role, schema role overwrites default role.
func (host *Host) MergePermissions() {
	for _, schema := range host.Schemas {
		roles := []*Role{}

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
