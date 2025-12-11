package config

import (
	"os"
	"path/filepath"
	"sync"

	"sigs.k8s.io/yaml"
)

var _ Persistence = &YamlPersistence{}

// YamlPersistence handles persisting user config to disk as a YAML file
type YamlPersistence struct {
	mu   sync.Mutex
	name string
}

// This saves the user part of the config
func (p *YamlPersistence) Save(c UserConfig) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	temp, err := func() (string, error) {
		// save to a temp file first
		t, err := os.CreateTemp(filepath.Dir(p.name), "user*")
		if err != nil {
			// creation failed
			return "", err
		}
		defer func() {
			_ = t.Close()
		}()

		// marshal yaml
		y, err := yaml.Marshal(c)
		if err != nil {
			return t.Name(), err
		}

		// write config
		if _, err := t.Write(y); err != nil {
			return t.Name(), err
		}

		// return name and no error
		return t.Name(), nil
	}()

	// ensure temp file is removed it it was created
	if temp != "" {
		defer func() {
			_ = os.Remove(temp)
		}()
	}

	// check save to temp was ok
	if err != nil {
		return err
	}

	// move into place
	return os.Rename(temp, p.name)
}
