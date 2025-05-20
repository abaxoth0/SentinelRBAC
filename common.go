package rbac

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

func load[T any](path string) (*T, error) {
    debugLog("[ RBAC ] Loading '"+path+"'...")

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New("RBAC host configuration file wasn't found")
		}

		return nil, err
	}
	defer func() {
		if err = file.Close(); err != nil {
			debugLog(err.Error())
			os.Exit(1)
		}
	}()

	buf, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	raw := new(T)
	if err := json.NewDecoder(bytes.NewReader(buf)).Decode(raw); err != nil {
		return nil, errors.New("Failed to parse RBAC host configuration file: " + err.Error())
	}

    debugLog("[ RBAC ] Loading '"+path+"': OK")

	return raw, nil
}

func validateDefaultRoles(roles []Role, defaultRoles []Role) error {
    rolesAmount := len(roles)

    for _, defaultRole := range defaultRoles {
        for i, role := range roles {
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

