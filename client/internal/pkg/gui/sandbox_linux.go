package gui

import (
	"net"
	"path/filepath"
	"strconv"

	"github.com/landlock-lsm/go-landlock/landlock"
)

func sandbox(systemConfig, userConfig, logDir, listenAddr string) error {
	_, p, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return err
	}

	port, err := strconv.ParseUint(p, 10, 16)
	if err != nil {
		return err
	}

	return landlock.V5.BestEffort().Restrict(
		landlock.ROFiles(systemConfig),
		landlock.RWDirs(filepath.Dir(userConfig)),
		landlock.RWFiles(userConfig),
		landlock.RWDirs(logDir),
		landlock.BindTCP(uint16(port)),
		landlock.ConnectTCP(53),
		landlock.ConnectTCP(443),
	)
}
