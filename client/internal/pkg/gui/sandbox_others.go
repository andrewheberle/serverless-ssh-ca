//go:build !linux

package gui

func sandbox(systemConfig, userConfig, logDir, listenAddr string) error {
	return nil
}
