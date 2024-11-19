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

// Only one instance of schema must exist at a time.
type schema struct {
	isLoaded bool
	// Role wich will have all new users, must correspond with one of the default roles' name. (optional)
	OriginRoleName string     `json:"origing-role,omitempty"`
	DefaultRoles   []*Role    `json:"default-roles"`
	Services       []*Service `json:"services"`
}

var Schema *schema

type SchemaBuilder struct {
	s *schema
}

func NewSchemaBuilder() *SchemaBuilder {
	return &SchemaBuilder{
		s: &schema{
			isLoaded: false,
		},
	}
}

// Build validates the configuration, merges service permissions with default roles'
// permissions and sets rbac.Schema to the built configuration.
//
// If the configuration is invalid, it returns an error.
//
// Otherwise, it returns nil.
func (builder *SchemaBuilder) Build() error {
	if err := validateSchema(builder.s); err != nil {
		return err
	}

	mergeServicePermissions(builder.s)

	builder.s.isLoaded = true

	Schema = builder.s

	return nil
}

func (builder *SchemaBuilder) Reset() *SchemaBuilder {
	builder.s = &schema{
		isLoaded: false,
	}

	return builder
}

func (builder *SchemaBuilder) SetDefaultRoles(defaultRoles []*Role) *SchemaBuilder {
	builder.s.DefaultRoles = defaultRoles

	return builder
}

func (builder *SchemaBuilder) AddDefaultRole(role *Role) *SchemaBuilder {
	builder.s.DefaultRoles = append(builder.s.DefaultRoles, role)

	return builder
}

func (builder *SchemaBuilder) RemoveDefaultRole(roleName string) *SchemaBuilder {
	for i, role := range builder.s.DefaultRoles {
		if role.Name == roleName {
			builder.s.DefaultRoles = append(builder.s.DefaultRoles[:i], builder.s.DefaultRoles[i+1:]...)
			break
		}
	}

	return builder
}

func (builder *SchemaBuilder) SetOriginRoleName(roleName string) *SchemaBuilder {
	builder.s.OriginRoleName = roleName

	return builder
}

func (builder *SchemaBuilder) SetServices(services []*Service) *SchemaBuilder {
	builder.s.Services = services

	return builder
}

func (builder *SchemaBuilder) AddService(service *Service) *SchemaBuilder {
	builder.s.Services = append(builder.s.Services, service)

	return builder
}

func (builder *SchemaBuilder) RemoveService(serviceName string) *SchemaBuilder {
	for i, service := range builder.s.Services {
		if service.Name == serviceName {
			builder.s.Services = append(builder.s.Services[:i], builder.s.Services[i+1:]...)
			break
		}
	}

	return builder
}

// Reads the RBAC configuration file from the given path,
// parses it and sets the Schema variable to the parsed configuration.
// After loading, it checks the configuration for errors and returns an error if any were found.
// If the configuration contains services, it merges their permissions with the default roles' permissions.
func LoadSchema(path string) error {
	log.Println("[ RBAC ] Loading configuration...")

	file, err := os.Open(path)

	if err != nil {
		if os.IsNotExist(err) {
			return errors.New("RBAC configuration file wasn't found")
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

	Schema = &schema{}

	if err := json.NewDecoder(bytes.NewReader(buf)).Decode(Schema); err != nil {
		return errors.New("[ RBAC ] Failed to parse RBAC configuration file: " + err.Error())
	}

	log.Println("[ RBAC ] Loading configuration: OK")

	log.Println("[ RBAC ] Checking configuration...")

	if err = validateSchema(Schema); err != nil {
		return err
	}

	log.Println("[ RBAC ] Checking configuration: OK")

	log.Println("[ RBAC ] Merging services permissions...")

	mergeServicePermissions(Schema)

	log.Println("[ RBAC ] Merging service permissions: OK")

	return nil
}

func validateSchema(schema *schema) error {
	if len(schema.Services) == 0 {
		return errors.New("no services defined")
	}

	isOriginRoleFound := false

	for _, defaultRole := range schema.DefaultRoles {
		if defaultRole.Name == schema.OriginRoleName {
			isOriginRoleFound = true
		}

		for _, permission := range defaultRole.Permissions {
			if !slices.Contains(permissions[:], permission) {
				err := fmt.Sprintf("invalid permission \"%s\" in default role: \"%s\"", string(permission), defaultRole.Name)
				return errors.New(err)
			}
		}
	}

	if schema.OriginRoleName != "" && !isOriginRoleFound {
		err := fmt.Sprintf("invalid origing role \"%s\", it must be one of the default roles' names", schema.OriginRoleName)
		return errors.New(err)
	}

	for _, service := range schema.Services {
		for _, serviceRole := range service.Roles {
			for _, permission := range serviceRole.Permissions {
				if !slices.Contains(permissions[:], permission) {
					err := fmt.Sprintf("invalid permission \"%s\" in \"%s\" role: \"%s\"", string(permission), service.Name, serviceRole.Name)
					return errors.New(err)
				}
			}
		}
	}

	return nil
}

// Merges permissions from service specific roles with default roles.
// If service has a role with the same name as default role, service role overwrites default role.
func mergeServicePermissions(schema *schema) {
	for _, service := range schema.Services {
		var roles []*Role = []*Role{}

		for _, serviceRole := range service.Roles {
			for _, defaultRole := range schema.DefaultRoles {
				if serviceRole.Name == defaultRole.Name {
					roles = append(roles, serviceRole)
				} else {
					roles = append(roles, defaultRole)
				}
			}
		}

		if service.Roles == nil {
			roles = schema.DefaultRoles
		}

		service.Roles = roles
	}
}
