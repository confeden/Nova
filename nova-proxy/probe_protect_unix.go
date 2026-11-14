//go:build !windows

// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"errors"
	"net"
	"syscall"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
)

// protectHook sends the socket's descriptor (SCM_RIGHTS) to the host app listening on the
// abstract unix socket `name`, and waits for one byte back: 1 = bound, anything else = refused.
// Android's Network.bindSocket works on a descriptor of the app's own uid, which this
// helper process cannot do for itself.
func protectHook(name string) (dialer.SocketControl, error) {
	if name == "" {
		return nil, errors.New("empty protect socket name")
	}
	return func(network, address string, c syscall.RawConn) error {
		var sendErr error
		if err := c.Control(func(fd uintptr) { sendErr = sendDescriptor(name, int(fd)) }); err != nil {
			return err
		}
		return sendErr
	}, nil
}

func sendDescriptor(name string, fd int) error {
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: "@" + name, Net: "unix"})
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := conn.WriteMsgUnix([]byte{1}, syscall.UnixRights(fd), nil); err != nil {
		return err
	}
	ack := make([]byte, 1)
	if _, err := conn.Read(ack); err != nil {
		return err
	}
	if ack[0] != 1 {
		return errors.New("host refused to bind the socket")
	}
	return nil
}
