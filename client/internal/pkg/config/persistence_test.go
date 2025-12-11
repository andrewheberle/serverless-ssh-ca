package config

import (
	"os"
	"reflect"
	"testing"

	"sigs.k8s.io/yaml"
)

func TestYamlPersistence_Save(t *testing.T) {
	tests := []struct {
		name    string
		c       UserConfig
		p       *YamlPersistence
		wantErr bool
	}{
		{
			"test save",
			UserConfig{
				Certificate:  []byte("cert"),
				PrivateKey:   []byte("key"),
				RefreshToken: []byte("token"),
			},
			&YamlPersistence{
				name: "testdata/ignored.yml",
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotErr := tt.p.Save(tt.c)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("Save() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("Save() succeeded unexpectedly")
			}

			var got UserConfig
			b, err := os.ReadFile(tt.p.name)
			if err != nil {
				t.Fatalf("Could not read file from Save(): %v", err)
			}

			if err := yaml.Unmarshal(b, &got); err != nil {
				t.Fatalf("Could not parse file from Save(): %v", err)
			}

			if !reflect.DeepEqual(got, tt.c) {
				t.Errorf("Save() = %v, want %v", got, tt.c)
			}
		})
	}
}
