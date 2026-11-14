//go:build windows

// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"errors"

	"github.com/metacubex/mihomo/component/dialer"
)

// protectHook exists on Android/Linux only; Windows binds by adapter (-interface).
func protectHook(string) (dialer.SocketControl, error) {
	return nil, errors.New("-protect is not supported on Windows; use -interface")
}
