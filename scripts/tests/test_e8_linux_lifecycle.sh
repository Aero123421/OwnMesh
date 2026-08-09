#!/usr/bin/env sh
# Opt-in receipt for the Linux root-owned privileged broker service.
set -eu

if [ "${OWNMESH_E8_ROOT:-}" != "1" ]; then
  echo "SKIP: set OWNMESH_E8_ROOT=1 to run a real root/systemd lifecycle receipt" >&2
  exit 0
fi
if [ "$(id -u)" != 0 ]; then
  echo "OWNMESH_E8_ROOT=1 requires effective UID 0" >&2
  exit 2
fi
if ! systemctl is-system-running >/dev/null 2>&1; then
  echo "systemd is not running" >&2
  exit 2
fi

broker=${OWNMESH_E8_BROKER:-target/debug/ownmesh-broker}
receipt_client=${OWNMESH_E8_RECEIPT_CLIENT:-target/debug/examples/e8_lifecycle_client}
if [ ! -x "$broker" ]; then
  echo "build ownmesh-broker first, or set OWNMESH_E8_BROKER" >&2
  exit 2
fi
if [ ! -x "$receipt_client" ]; then
  cargo build -p ownmesh-broker --example e8_lifecycle_client
fi
if [ ! -x "$receipt_client" ]; then
  echo "receipt client build failed" >&2
  exit 2
fi
# The source must be root-controlled before the installer will copy it as the
# trusted ownmeshd image. This is a test-only copy; production supplies ownmeshd.
trusted=/root/ownmesh-e8-lifecycle-client
cp "$receipt_client" "$trusted"
chown root:root "$trusted"
chmod 0755 "$trusted"

daemon_user=${OWNMESH_E8_DAEMON_USER:-ownmesh-e8-test}
if ! id "$daemon_user" >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin "$daemon_user"
fi
daemon_uid=$(id -u "$daemon_user")
daemon_gid=$(id -g "$daemon_user")
if [ "$daemon_uid" = 0 ] || [ "$daemon_gid" = 0 ]; then
  echo "test daemon account must be non-root" >&2
  exit 2
fi

"$broker" uninstall || true
if env -u SUDO_UID -u SUDO_GID "$broker" install --trusted-executable "$trusted"; then
  echo "direct-root install without an explicit daemon identity unexpectedly succeeded" >&2
  exit 1
fi
"$broker" install --trusted-executable "$trusted" --daemon-uid "$daemon_uid" --daemon-gid "$daemon_gid"
"$broker" status | grep -q 'status=installed support=supported network=disabled'
test "$(stat -c %u:%g /run/ownmesh/broker.sock)" = "$daemon_uid:$daemon_gid"
test "$(stat -c %a /run/ownmesh/broker.sock)" = 600
test "$(stat -c %u:%g /var/lib/ownmesh/broker/broker.secret)" = "$daemon_uid:$daemon_gid"
runuser -u "$daemon_user" -- test -r /var/lib/ownmesh/broker/broker.secret
runuser -u nobody -- sh -c '! test -r /var/lib/ownmesh/broker/broker.secret'
runuser -u "$daemon_user" -- /usr/lib/ownmesh/ownmeshd \
  --secret /var/lib/ownmesh/broker/broker.secret \
  --socket /run/ownmesh/broker.sock \
  --program "$(readlink -f /bin/true)"
# Root can bypass DAC, so this specifically proves SO_PEERCRED policy rejects
# an untrusted root peer after connect rather than treating filesystem access
# as authorization.
python3 - <<'PY'
import json, socket
s = socket.socket(socket.AF_UNIX)
s.settimeout(3)
s.connect('/run/ownmesh/broker.sock')
s.sendall(b'{}\n')
response = json.loads(s.recv(4096).decode())
if response.get('ok') or not response.get('error'):
    raise SystemExit(f'root peer unexpectedly authorized: {response!r}')
PY
if command -v ss >/dev/null 2>&1 && ss -ltnp 2>/dev/null | grep -q ownmesh-broker; then
  echo "broker unexpectedly owns a TCP listener" >&2
  exit 1
fi
systemctl stop ownmesh-broker.service
test "$(systemctl is-active ownmesh-broker.service)" = inactive
systemctl start ownmesh-broker.service
"$broker" status | grep -q 'status=installed'
"$broker" install --trusted-executable "$trusted" --daemon-uid "$daemon_uid" --daemon-gid "$daemon_gid" # exact idempotent reinstall
if "$broker" install --trusted-executable "$trusted" --daemon-uid 1 --daemon-gid 1; then
  echo "identity-mismatched reinstall unexpectedly succeeded" >&2
  exit 1
fi

# Custody corruption must not be silently repaired or accepted.
chmod 0644 /etc/ownmesh/ownmesh-broker.json
if "$broker" status; then
  echo "corrupt config unexpectedly accepted" >&2
  exit 1
fi
chmod 0600 /etc/ownmesh/ownmesh-broker.json

"$broker" uninstall
"$broker" uninstall
test ! -e /etc/systemd/system/ownmesh-broker.service
echo "E8 Linux lifecycle receipt: PASS"
