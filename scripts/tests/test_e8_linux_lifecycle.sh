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
trusted=${OWNMESH_E8_TRUSTED_EXECUTABLE:-target/debug/ownmeshd}
if [ ! -x "$broker" ] || [ ! -x "$trusted" ]; then
  echo "build broker and ownmeshd first, or set OWNMESH_E8_BROKER and OWNMESH_E8_TRUSTED_EXECUTABLE" >&2
  exit 2
fi

"$broker" uninstall || true
"$broker" install --trusted-executable "$trusted"
"$broker" status | grep -q 'status=installed support=supported network=disabled'
systemctl stop ownmesh-broker.service
test "$(systemctl is-active ownmesh-broker.service)" = inactive
systemctl start ownmesh-broker.service
"$broker" status | grep -q 'status=installed'
"$broker" install --trusted-executable "$trusted" # exact idempotent reinstall

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
