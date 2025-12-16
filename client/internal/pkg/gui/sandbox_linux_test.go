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
		{"should pass", "/a/apth/to/somewhere.yml", "/a/apth/to/somewhere/else.yml", "/a/path/to/logs", "localhost:3000", false},
		{"expected to fail with no port", "/a/apth/to/somewhere.yml", "/a/apth/to/somewhere/else.yml", "/a/path/to/logs", "localhost", true},
		{"expected to fail with number too big", "/a/apth/to/somewhere.yml", "/a/apth/to/somewhere/else.yml", "/a/path/to/logs", "localhost:99000", true},
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
