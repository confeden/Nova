// Package registry registers client protocols and transports for Xray-native profiles.
//
// Mihomo handles the broader subscription ecosystem in a separate helper.
// Native Xray outbounds retain their original transport and obfuscation options.
//
// Любой транспорт, который умеет отдавать генератор конфигурации
// (VlessXrayConfig.kt), обязан быть здесь — иначе ядро примет конфигурацию,
// но упадёт при подключении.
package registry

import (
	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"

	_ "github.com/xtls/xray-core/proxy/freedom"
	// proxy/http — входящий HTTP CONNECT. Нужен, когда профиль VLESS занимает слот
	// дополнительного VPN: его потребители (tcp_proxy.py, релей Telegram, планы транспорта)
	// ходят в один порт CONNECT под замороженной меткой «opera-http», тогда как основной слот
	// берёт только SOCKS5. Без этой строки ядро примет конфигурацию с таким входящим и упадёт
	// при запуске — то же правило, что и для транспортов ниже.
	_ "github.com/xtls/xray-core/proxy/http"
	_ "github.com/xtls/xray-core/proxy/hysteria"
	_ "github.com/xtls/xray-core/proxy/shadowsocks"
	_ "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	_ "github.com/xtls/xray-core/proxy/socks"
	_ "github.com/xtls/xray-core/proxy/trojan"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"
	_ "github.com/xtls/xray-core/proxy/vmess/outbound"
	_ "github.com/xtls/xray-core/proxy/wireguard"

	_ "github.com/xtls/xray-core/transport/internet/grpc"
	_ "github.com/xtls/xray-core/transport/internet/httpupgrade"
	_ "github.com/xtls/xray-core/transport/internet/hysteria"
	_ "github.com/xtls/xray-core/transport/internet/kcp"
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/splithttp"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/tls"
	_ "github.com/xtls/xray-core/transport/internet/udp"
	_ "github.com/xtls/xray-core/transport/internet/websocket"

	_ "github.com/xtls/xray-core/transport/internet/headers/http"
	_ "github.com/xtls/xray-core/transport/internet/headers/noop"
)
