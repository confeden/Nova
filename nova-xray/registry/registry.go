// Package registry регистрирует протоколы и транспорты, нужные Nova.
//
// Вместо main/distro/all — только клиентская часть: серверные входящие,
// wireguard, hysteria и shadowsocks Nova не использует. Экономия по размеру
// небольшая (JSON-загрузчик всё равно тянет конфигурационные типы всех
// протоколов), но набор зарегистрированного соответствует тому, что реально
// может прийти в ссылке vless://.
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
	_ "github.com/xtls/xray-core/proxy/socks"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"

	_ "github.com/xtls/xray-core/transport/internet/grpc"
	_ "github.com/xtls/xray-core/transport/internet/httpupgrade"
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
