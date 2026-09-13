// Package novago pins the dependency graph of nova-go.exe. It is imported by nothing; the blank
// imports only keep `go mod tidy` from dropping modules that the helper packages are written against.
package novago

import (
	_ "github.com/Diniboy1123/connect-ip-go"
	_ "github.com/Diniboy1123/usque/api"
	_ "github.com/Diniboy1123/usque/models"
	_ "github.com/bepass-org/warp-plus/ipscanner"
	_ "github.com/bepass-org/warp-plus/warp"
	_ "github.com/quic-go/quic-go"
	_ "github.com/quic-go/quic-go/http3"
	_ "github.com/refraction-networking/utls"
	_ "github.com/things-go/go-socks5"
	_ "github.com/yosida95/uritemplate/v3"
	_ "golang.org/x/net/http2"
	_ "golang.org/x/sys/windows"
	_ "golang.zx2c4.com/wireguard/tun/netstack"
)
