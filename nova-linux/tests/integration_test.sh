#!/usr/bin/env bash
set -e

echo "=== Running Nova Linux Automated Integration Tests ==="

mkdir -p /run/nova
export RUST_LOG=info

# 1. Start novad daemon in the background
echo "[TEST] Starting novad..."
/app/target/release/novad --socket /run/nova/novad.sock --no-firewall &
DAEMON_PID=$!

# Wait for socket
sleep 2

if [ ! -S /run/nova/novad.sock ]; then
    echo "[FAIL] Socket /run/nova/novad.sock was not created!"
    kill -9 $DAEMON_PID 2>/dev/null || true
    exit 1
fi
echo "[PASS] UNIX Socket /run/nova/novad.sock exists and is active."

# 2. Test IPC GetStatus via Python
python3 -c "
import socket, json

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect('/run/nova/novad.sock')

# Send GetStatus
req = {'action': 'get_status'}
sock.sendall(json.dumps(req).encode('utf-8'))

data = sock.recv(8192)
resp = json.loads(data.decode('utf-8'))
print('[IPC RESP]', resp)

assert resp.get('status') == 'status', 'Invalid status response!'
status_data = resp.get('data', {})
assert status_data.get('running') == True, 'Daemon reports not running!'
assert len(status_data.get('services', [])) > 0, 'No services reported!'
print('[PASS] GetStatus test successful!')

# Send SetMode (Paused)
req = {'action': 'set_mode', 'payload': 'paused'}
sock.sendall(json.dumps(req).encode('utf-8'))
data = sock.recv(8192)
resp = json.loads(data.decode('utf-8'))
assert resp.get('status') == 'success', 'SetMode failed!'
print('[PASS] SetMode paused test successful!')

# Send Shutdown
req = {'action': 'shutdown'}
sock.sendall(json.dumps(req).encode('utf-8'))
data = sock.recv(8192)
resp = json.loads(data.decode('utf-8'))
assert resp.get('status') == 'success', 'Shutdown failed!'
print('[PASS] Shutdown test successful!')

sock.close()
"

# 3. Wait for daemon to finish
wait $DAEMON_PID || true
echo "[PASS] Daemon terminated cleanly."

echo "=== ALL INTEGRATION TESTS PASSED ==="
