package main

import (
	"fmt"
	"net"
	"os"
	"syscall"
)

type containerPeer struct {
	PID      int32
	UID, GID uint32
}

func readContainerPeer(conn net.Conn) (containerPeer, error) {
	u, ok := conn.(*net.UnixConn)
	if !ok {
		return containerPeer{}, fmt.Errorf("not a Unix connection")
	}
	raw, err := u.SyscallConn()
	if err != nil {
		return containerPeer{}, err
	}
	var cred *syscall.Ucred
	var inner error
	err = raw.Control(func(fd uintptr) {
		cred, inner = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil || inner != nil || cred == nil {
		return containerPeer{}, fmt.Errorf("peer credentials unavailable")
	}
	return containerPeer{PID: cred.Pid, UID: cred.Uid, GID: cred.Gid}, nil
}

func containerSocketOwner(info os.FileInfo, uid uint32) bool {
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Uid == uid
}
