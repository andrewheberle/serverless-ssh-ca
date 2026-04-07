package client

import (
	"fmt"
	"runtime"
	"testing"
)

func Test_GenerateUserAgent(t *testing.T) {
	tests := []struct {
		name    string
		appName string
		want    string
	}{
		{"basic", UserAgent, fmt.Sprintf("%s/%s (%s-%s)", UserAgent, "(devel)", runtime.GOOS, runtime.GOARCH)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GenerateUserAgent(tt.appName)
			if tt.want != got {
				t.Errorf("GenerateUserAgent() = %v, want %v", got, tt.want)
			}
		})
	}
}
