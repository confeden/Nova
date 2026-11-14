// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"net"

	"github.com/metacubex/mihomo/component/dialer"
)

// Probes measure the provider's connection, not whatever VPN is active on the machine:
// a node reached through another tunnel answers with that tunnel's time, or not at all.
// Two ways to keep the sockets off it, both optional and both applied to every dial the
// probe makes (the preflight below and each protocol adapter):
//
//	-interface NAME   bind to the physical adapter (Windows, Linux, macOS)
//	-protect NAME     hand every socket to the host app over a unix socket before it
//	                  connects, so the app can pin it to a network (Android)
//
// Without either flag the sockets are ordinary ones.
func configureProbeBinding(iface, protect string) error {
	if iface != "" {
		dialer.DefaultInterface.Store(iface)
	}
	if protect != "" {
		hook, err := protectHook(protect)
		if err != nil {
			return err
		}
		dialer.DefaultSocketHook = hook
	}
	return nil
}

// probeDial is the bounded TCP preflight; it honours the same binding as the adapters.
func probeDial(ctx context.Context, address string) (net.Conn, error) {
	return dialer.DialContext(ctx, "tcp", address)
}
