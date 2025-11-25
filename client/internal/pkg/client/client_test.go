package client

import (
	"fmt"
	"runtime"
	"testing"
)

func Test_getUserAgent(t *testing.T) {
	tests := []struct {
		name    string
		appName string
		want    string
	}{
		{"basic", UserAgent, fmt.Sprintf("%s/%s (%s-%s)", UserAgent, "(devel)", runtime.GOOS, runtime.GOARCH)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getUserAgent(tt.appName)
			// TODO: update the condition below to compare got with tt.want.
			if tt.want != got {
				t.Errorf("getUserAgent() = %v, want %v", got, tt.want)
			}
		})
	}
}
