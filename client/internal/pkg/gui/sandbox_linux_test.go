package gui

import "testing"

func Test_sandbox(t *testing.T) {
	tests := []struct {
		name         string
		systemConfig string
		userConfig   string
		logDir       string
		listenAddr   string
		wantErr      bool
	}{
		{"should pass", "/etc/config.yml", "/tmp/user.yml", "/var/log/tray.log", "localhost:3000", false},
		{"should still with invalid path", "/a/missing/path/config.yml", "/tmp/user.yml", "/var/log/tray.log", "localhost:3000", false},
		{"expected to fail with no port", "/etc/config.yml", "/tmp/user.yml", "/var/log/tray.log", "localhost", true},
		{"expected to fail with number too big", "/etc/config.yml", "/tmp/user.yml", "/var/log/tray.log", "localhost:99000", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotErr := sandbox(tt.systemConfig, tt.userConfig, tt.logDir, tt.listenAddr)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("sandbox() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("sandbox() succeeded unexpectedly")
			}
		})
	}
}
