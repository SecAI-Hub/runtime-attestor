//go:build !linux

package main

import (
	"fmt"
	"net"
	"os"
)

type containerPeer struct {
	PID      int32
	UID, GID uint32
}

func readContainerPeer(net.Conn) (containerPeer, error) {
	return containerPeer{}, fmt.Errorf("container endpoint attestation requires Linux peer credentials")
}
func containerSocketOwner(os.FileInfo, uint32) bool { return false }
