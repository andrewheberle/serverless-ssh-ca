package config

import (
	"bytes"
	"sync"

	"codeberg.org/sdassow/atomic"
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

	y, err := yaml.Marshal(c)
	if err != nil {
		return err
	}

	return atomic.WriteFile(p.name, bytes.NewReader(y), atomic.FileMode(0600))
}
