//go:build !windows

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigDirs(t *testing.T) {

	{
		// set variable so we can test result
		if err := os.Setenv("XDG_CONFIG_HOME", "/home/testuser/.config"); err != nil {
			panic(err)
		}
		if err := os.Setenv("IGNORE_SNAP_DURING_TEST", "yes"); err != nil {
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

	// tests for snap
	{
		// set variables so we can test result
		if os.Getenv("SNAP_USER_COMMON") == "" {
			if err := os.Setenv("SNAP_USER_COMMON", "/home/testuser/snap/ssh-ca-client"); err != nil {
				panic(err)
			}
		}
		if os.Getenv("SNAP_COMMON") == "" {
			if err := os.Setenv("SNAP_COMMON", "/var/snap/ssh-ca-client/ssh-ca-client"); err != nil {
				panic(err)
			}
		}
		if err := os.Unsetenv("IGNORE_SNAP_DURING_TEST"); err != nil {
			// unset this so previous tests dont cause problems
			panic(err)
		}

		tests := []struct {
			name    string
			want    string
			want2   string
			wantErr bool
		}{
			{"test results", os.Getenv("SNAP_USER_COMMON"), os.Getenv("SNAP_COMMON"), false},
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

}
