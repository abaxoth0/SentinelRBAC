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

type Role struct {
	Name        string          `json:"name"`
	Permissions []PermissionTag `json:"permissions"`
}

type Service struct {
	// uuid format
	ID    string `json:"id"`
	Name  string `json:"name"`
	Roles []Role `json:"roles,omitempty"`
}

type Schema struct {
	Roles    []Role    `json:"roles"`
	Services []Service `json:"services"`
}

var RBAC *Schema

// Opens and reads "RBAC.json" file which contains role and permission definitions and returns the parsed configuration.
//
// This function will stop app if it can't read RBAC configuration file, or build RBAC schema.
func Load() *Schema {
	log.Println("[ RBAC ] Loading configuration...")

	file, err := os.Open("RBAC.json")

	if err != nil {
		if !os.IsExist(err) {
			log.Println("[ CRITICAL ERROR ] RBAC configuration file wasn't found")
			os.Exit(1)
		}

		log.Println(err.Error())
		os.Exit(1)
	}

	// If something will panic, this will be called anyway, unlike if i use this at the end.
	defer func() {
		if err = file.Close(); err != nil {
			log.Println(err.Error())
			os.Exit(1)
		}
	}()

	buf, err := io.ReadAll(file)

	if err != nil {
		log.Println(err.Error())
		os.Exit(1)
	}

	var RBAC Schema

	if err := json.NewDecoder(bytes.NewReader(buf)).Decode(&RBAC); err != nil {
		log.Println("[ CRITICAL ERROR ] Failed to parse RBAC configuration file")
		os.Exit(1)
	}

	log.Println("[ RBAC ] Loading configuration: OK")

	log.Println("[ RBAC ] Checking configuration...")

	if err = check(&RBAC); err != nil {
		log.Println(err.Error())
		os.Exit(1)
	}

	log.Println("[ RBAC ] Checking configuration: OK")

	return &RBAC
}

func IsLoaded() bool {
	return RBAC != nil
}

func check(RBAC *Schema) error {
	for _, globalRole := range RBAC.Roles {
		for _, permission := range globalRole.Permissions {
			if !slices.Contains(PermissionTags, permission) {
				err := fmt.Sprintf("invalid permission \"%s\" in global role: \"%s\"", string(permission), globalRole.Name)
				return errors.New(err)
			}
		}
	}

	for _, service := range RBAC.Services {
		for _, serviceRole := range service.Roles {
			for _, permission := range serviceRole.Permissions {
				if !slices.Contains(PermissionTags, permission) {
					err := fmt.Sprintf("invalid permission \"%s\" in \"%s\" role: \"%s\"", string(permission), service.Name, serviceRole.Name)
					return errors.New(err)
				}
			}
		}
	}

	return nil
}
