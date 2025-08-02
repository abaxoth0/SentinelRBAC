package rbac

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
)

type loadable[T any] interface {
    NormalizeAndValidate() (T, error)
}

// postLoad is called after file was loaded and parsed, but before normalization and validation.
func load[T any, R loadable[T]](path string, postLoad func(*R)) (T, error) {
    var zero T

    Debug.Log("[ RBAC ] Loading '"+path+"'...")

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return zero, errors.New("RBAC host configuration file wasn't found")
		}

		return zero, err
	}
	defer func() {
		if err = file.Close(); err != nil {
			Debug.Log(err.Error())
			os.Exit(1)
		}
	}()

	buf, err := io.ReadAll(file)
	if err != nil {
		return zero, err
	}

    var raw R
	if err := json.NewDecoder(bytes.NewReader(buf)).Decode(&raw); err != nil {
		return zero, errors.New("Failed to parse RBAC host configuration file: " + err.Error())
	}

    if postLoad != nil {
        postLoad(&raw)
    }

    result, err := raw.NormalizeAndValidate()
    if err != nil {
        return zero, err
    }

    Debug.Log("[ RBAC ] Loading '"+path+"': OK")

	return result, nil
}

