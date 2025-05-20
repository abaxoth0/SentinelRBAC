package rbac

type Config struct {
	// (Optional)
    //
    // Roles wich will have all new users, each default role must correspond with one of existing global roles.
    DefaultRoles []Role
    Roles        []Role
}

func (c *Config) Validate() error {
    debugLog("[ RBAC ] Validating configuration...")

    if err := validateDefaultRoles(c.Roles, c.DefaultRoles); err != nil {
        return err
    }

    debugLog("[ RBAC ] Validating configuration: OK")

    return nil
}

// Reads RBAC configuration file from the given path.
// After loading and normalizing, it validates the configuration and returns an error if any of them were detected.
func LoadConfig(path string) (Config, error) {
    var zero Config

    raw, err := load[rawConfig](path)
    if err != nil {
        return zero, err
    }

    config := raw.Normalize()

	if err = config.Validate(); err != nil {
		return zero, err
	}

	return *config, nil
}

