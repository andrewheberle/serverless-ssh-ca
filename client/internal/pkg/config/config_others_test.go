//go:build !windows

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigDirs(t *testing.T) {
	// set variable so we can test result
	if err := os.Setenv("XDG_CONFIG_HOME", "/home/testuser/.config"); err != nil {
		panic(err)
	}

	tests := []struct {
		name    string
		want    string
		want2   string
		wantErr bool
	}{
		{"test results", filepath.Join("/home/testuser/.config", AppName), filepath.Join("/etc", AppName), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got2, gotErr := ConfigDirs()
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("ConfigDirs() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("ConfigDirs() succeeded unexpectedly")
			}
			if got != tt.want {
				t.Errorf("ConfigDirs() = %v, want %v", got, tt.want)
			}
			if got2 != tt.want2 {
				t.Errorf("ConfigDirs() = %v, want %v", got2, tt.want2)
			}
		})
	}
}
