#!/bin/bash
# Linux-host side of integration-test/windows-node-test.md (zipline#162).
#
# The Windows VM runs `ph node`; this script builds everything else: keys,
# policy and configs (`prepare`, run on the host), then valkey, the visa
# service, the visa service's adapter and two client adapters in network
# namespaces (`up`, run inside the zpr-integration-test container with
# --network host), and tears it down again (`down`). The document is the
# authority on what this builds and why; keep the two in sync.
#
# Deliberately NOT named *-test.sh: the Makefile's docker-test target sweeps
# that glob, and this script needs a Windows VM on the network, which the
# automated tier does not have.
#
# Usage:
#   export VM_LAN_IP=<Windows VM IP as seen from this host>
#   export WORK=$(mktemp -d /tmp/win-node.XXXX)
#   integration-test/windows-node-linux-host.sh prepare     # host, unprivileged
#   sudo -E integration-test/windows-node-linux-host.sh nat-up    # host, root
#   ... docker run (see windows-node-test.md) ...
#   integration-test/windows-node-linux-host.sh up          # container
#   integration-test/windows-node-linux-host.sh down        # container
#   sudo -E integration-test/windows-node-linux-host.sh nat-down  # host, root
#
# nat-up/nat-down run on the HOST, not in the container: the container joins
# the host network namespace (--network host) so the rules land in the same
# place either way, but the integration-test image carries no iptables and
# mounts /proc/sys read-only (first dry-run finding, zipline#162).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREGEN="$ROOT/integration-test/pregen"
ZPR_PKI="$ROOT/integration-test/lib/zpr-pki"

# Binaries: built in this checkout and its siblings; override via env.
PH_BIN="${PH_BIN:-$ROOT/target/debug/ph}"
PHCLI_BIN="${PHCLI_BIN:-$ROOT/target/debug/ph-cli}"
VS_BIN="${VS_BIN:-$ROOT/../zl-zpr-visaservice/target/debug/vs}"
ZPLC_BIN="${ZPLC_BIN:-$ROOT/../zl-zpr-compiler/target/debug/zplc}"

die() { echo "windows-node-linux-host.sh: $*" >&2; exit 1; }

[ -n "${WORK:-}" ] || die "WORK is not set (export WORK=\$(mktemp -d /tmp/win-node.XXXX))"
[ -n "${VM_LAN_IP:-}" ] || die "VM_LAN_IP is not set (the Windows VM's IP as seen from this host)"

# ---------------------------------------------------------------------------
# prepare: key material, policy, configs, compiled policy, VM staging dir.
# Run on the host (needs zplc and zpr-pki, nothing privileged).
# ---------------------------------------------------------------------------
prepare() {
    [ -x "$ZPLC_BIN" ] || die "zplc not found at $ZPLC_BIN (build zl-zpr-compiler, or set ZPLC_BIN)"
    mkdir -p "$WORK"

    # Key material. actor1 -> adapter1, actor2 -> adapter2, actorvs + a
    # generated vs.zpr noise cert for the visa service's adapter. The node's
    # material goes to the staging dir for the VM.
    cp "$PREGEN/ca-cert.pem"         "$WORK/ca.crt"
    cp "$PREGEN/ca-key.pem"          "$WORK/ca.key"
    cp "$PREGEN/actor1-rsa.key"      "$WORK/adapter1-rsa.key"
    cp "$PREGEN/actor1.pem"          "$WORK/adapter1.pem"
    cp "$PREGEN/actor2-rsa.key"      "$WORK/adapter2-rsa.key"
    cp "$PREGEN/actor2.pem"          "$WORK/adapter2.pem"
    cp "$PREGEN/actorvs-rsa.key"     "$WORK/actorvs-rsa.key"
    cp "$PREGEN/actorvs.pem"         "$WORK/actorvs.pem"
    cp "$PREGEN/node-rsa-pubkey.pem" "$WORK/node-rsa-pubkey.pem"

    # Noise cert for the visa-service adapter (CN must be vs.zpr).
    "$ZPR_PKI" genkey > "$WORK/vs.zpr.key"
    "$ZPR_PKI" pubkey < "$WORK/vs.zpr.key" > "$WORK/vs.zpr.pubkey"
    "$ZPR_PKI" gensignedcert "$WORK/ca.crt" "$WORK/ca.key" \
        /CN=vs.zpr 1 < "$WORK/vs.zpr.pubkey" > "$WORK/vs.zpr.crt"

    # Staging dir: everything the Windows VM needs, in one place.
    mkdir -p "$WORK/vm"
    cp "$PREGEN/ca-cert.pem"       "$WORK/vm/ca.crt"
    cp "$PREGEN/node-cert.pem"     "$WORK/vm/node.crt"
    cp "$PREGEN/node.key"          "$WORK/vm/node.key"
    cp "$PREGEN/node-rsa-key.pem"  "$WORK/vm/node-rsa-key.pem"

    # The policy: the Windows VM is the node; adapter2 serves ping + HTTP
    # :8080 to adapter1, adapter1 serves ping back. Every packet between
    # them is forwarded by the VM.
    cat > "$WORK/windows-node.zpl" <<'EOF'
# Windows node test policy (integration-test/windows-node-test.md).

define adapter as a device with zpr.adapter.cn.

define A1 as adapter with zpr.adapter.cn:adapter1.
define A2 as adapter with zpr.adapter.cn:adapter2.

define A1Ping as a service with device.zpr.adapter.cn:adapter1.
define A2Ping as a service with device.zpr.adapter.cn:adapter2.
define A2Web as a service with device.zpr.adapter.cn:adapter2.

allow A1 to access A2Ping.
allow A1 to access A2Web.
allow A2 to access A1Ping.

# Admin access to VS
define VsAdmin as a device with zpr.adapter.cn:'client.zpr.org'.
allow VsAdmin to access VisaService.
EOF

    cat > "$WORK/windows-node.zplc" <<EOF
# -*- mode: toml -*-

[resolver]
order = ["hosts", "dns"]

[resolver.hosts]
"n0.zpr" = "fd5a:5052::2"
"n0.overlay" = "$VM_LAN_IP"

[nodes."node"]
provider = [ [ "device.zpr.adapter.cn", "node" ] ]
zpr_address = "n0.zpr"

[nodes."node".substrate_addrs]
in1 = "n0.overlay:5000"

[trusted_services.default]
cert_path = "ca.crt"

# The addresses file store grants each adapter its static ZPR address
# (device.zpr_addr, zipline#99). Data: addresses.json next to the vs config.
[trusted_services.addresses]
api = "file"
returns_attributes = ["zpr_addr -> device.zpr_addr"]
expiration_seconds = 3600

[visa_service]
dock_node = "node"

[bootstrap]
"node" = "node-rsa-pubkey.pem"
"vs.zpr" = "actorvs.pem"
"adapter1" = "adapter1.pem"
"adapter2" = "adapter2.pem"

[protocols.ping]
l4protocol = "iana.ICMP6"
icmp_type = "request-response"
icmp_codes = [ 128, 129 ]

[protocols.http]
l4protocol = "iana.TCP"
port = 8080

[services.A1Ping]
protocol = "ping"
provider = [["device.zpr.adapter.cn", "adapter1"]]

[services.A2Ping]
protocol = "ping"
provider = [["device.zpr.adapter.cn", "adapter2"]]

[services.A2Web]
protocol = "http"
provider = [["device.zpr.adapter.cn", "adapter2"]]
EOF

    # Address grants for the two adapters.
    cat > "$WORK/addresses.json" <<'EOF'
{
  "device.zpr.adapter.cn": {
    "adapter1": { "zpr_addr": ["fd5a:5052:8888::1:1"] },
    "adapter2": { "zpr_addr": ["fd5a:5052:8888::2:1"] }
  }
}
EOF

    # Visa service config (admin identity from pregen, local valkey).
    cat > "$WORK/vs-config.toml" <<EOF
[core]
admin_cert = "$PREGEN/zpr-rsa-cert.pem"
admin_key = "$PREGEN/zpr-rsa-key.pem"
vk_uri = "redis://127.0.0.1:6379"
EOF

    # Content for the HTTP service behind adapter2: a directory listing to
    # eyeball and a 64 MiB blob for the throughput number (checklist item 4).
    mkdir -p "$WORK/www"
    [ -f "$WORK/www/blob" ] || dd if=/dev/urandom of="$WORK/www/blob" bs=1M count=64 status=none

    # Compile the policy; zplc prints the output name (windows-node.bin2).
    "$ZPLC_BIN" -c "$WORK/windows-node.zplc" -d "$WORK" "$WORK/windows-node.zpl"

    echo
    echo "prepare done."
    echo "  copy to the VM : $WORK/vm/{ca.crt,node.crt,node.key,node-rsa-key.pem}"
    echo "  next           : enter the container and run '$0 up' (see windows-node-test.md)"
}

# ---------------------------------------------------------------------------
# up: namespaces, NAT to the VM, valkey, vs, vs-adapter, adapter1, adapter2,
# HTTP server. Run inside the zpr-integration-test container (root, host
# network). Everything it starts records its PID in $WORK/pids.
# ---------------------------------------------------------------------------
up() {
    [ -x "$PH_BIN" ] || die "ph not found at $PH_BIN (make at the zl-zpr-core root, or set PH_BIN)"
    [ -x "$VS_BIN" ] || die "vs not found at $VS_BIN (make in zl-zpr-visaservice, or set VS_BIN)"
    [ -f "$WORK/windows-node.bin2" ] || die "no compiled policy in $WORK — run '$0 prepare' first"
    cd "$WORK"
    : > "$WORK/pids"

    # Namespaces: zpr-vs (valkey + vs + vs adapter), zpr-a1, zpr-a2. Each on
    # a veth /24 to the host namespace with a default route back, the same
    # layout as windows-adapter-test.md 1b — but here the node the adapters
    # dock to is on the VM, not this host, so the host forwards and
    # masquerades their traffic out to the LAN (removed by `down`).
    ip netns add zpr-vs; ip netns add zpr-a1; ip netns add zpr-a2
    ip -n zpr-vs link set lo up; ip -n zpr-a1 link set lo up; ip -n zpr-a2 link set lo up
    ip link add veth-zpr-vs type veth peer veth0 netns zpr-vs
    ip link add veth-zpr-a1 type veth peer veth0 netns zpr-a1
    ip link add veth-zpr-a2 type veth peer veth0 netns zpr-a2
    ip addr add 10.0.0.1/24 dev veth-zpr-vs; ip link set veth-zpr-vs up
    ip addr add 10.0.1.1/24 dev veth-zpr-a1; ip link set veth-zpr-a1 up
    ip addr add 10.0.2.1/24 dev veth-zpr-a2; ip link set veth-zpr-a2 up
    ip -n zpr-vs addr add 10.0.0.2/24 dev veth0; ip -n zpr-vs link set veth0 up
    ip -n zpr-a1 addr add 10.0.1.2/24 dev veth0; ip -n zpr-a1 link set veth0 up
    ip -n zpr-a2 addr add 10.0.2.2/24 dev veth0; ip -n zpr-a2 link set veth0 up
    ip -n zpr-vs route add default via 10.0.0.1
    ip -n zpr-a1 route add default via 10.0.1.1
    ip -n zpr-a2 route add default via 10.0.2.1

    # TUN interfaces, pre-created with the address already set — works
    # around the known Linux TUN bug described in docs/SETUP.md, required
    # whenever zpr_addr is specified.
    ip -n zpr-vs tuntap add name tun0 mode tun multi_queue
    ip -n zpr-vs link set tun0 mtu 1400 && ip -n zpr-vs link set tun0 up
    ip -n zpr-vs addr add fd5a:5052::1 peer fd5a:5052::2 dev tun0

    ip -n zpr-a1 tuntap add name tun0 mode tun multi_queue
    ip -n zpr-a1 link set tun0 mtu 1400 && ip -n zpr-a1 link set tun0 up
    ip -n zpr-a1 addr add fd5a:5052:8888::1:1 peer fd5a:5052::/32 dev tun0

    ip -n zpr-a2 tuntap add name tun0 mode tun multi_queue
    ip -n zpr-a2 link set tun0 mtu 1400 && ip -n zpr-a2 link set tun0 up
    ip -n zpr-a2 addr add fd5a:5052:8888::2:1 peer fd5a:5052::/32 dev tun0

    # valkey, then the visa service on it.
    ip netns exec zpr-vs valkey-server --save '' --appendonly no >valkey.log 2>&1 &
    echo $! >> "$WORK/pids"
    sleep 1

    ip netns exec zpr-vs "$VS_BIN" -c vs-config.toml --clear-state windows-node.bin2 >vs.log 2>&1 &
    echo $! >> "$WORK/pids"
    sleep 2

    # The visa service's adapter, docking to the node ON THE VM. The dock
    # retries in the background, so this works whether or not ph.exe is up
    # yet; the link goes Active on its own once it is.
    ip netns exec zpr-vs "$PH_BIN" adapter -l all=INFO \
        --control-path "$WORK/vs-adapter.sock" \
        --ca-file ca.crt --certificate-file vs.zpr.crt --private-key-file vs.zpr.key \
        --bootstrap-key actorvs-rsa.key \
        --tun-if tun0 --node-addr "$VM_LAN_IP:5000" --zpr-addr fd5a:5052::1 \
        >vs-adapter.log 2>&1 &
    echo $! >> "$WORK/pids"
    sleep 2

    ip netns exec zpr-a1 "$PH_BIN" adapter -l all=INFO \
        --control-path "$WORK/adapter1.sock" \
        --ca-file ca.crt --bootstrap-key adapter1-rsa.key --name adapter1 \
        --tun-if tun0 --node-addr "$VM_LAN_IP:5000" --zpr-addr fd5a:5052:8888::1:1 \
        >adapter1.log 2>&1 &
    echo $! >> "$WORK/pids"

    ip netns exec zpr-a2 "$PH_BIN" adapter -l all=INFO \
        --control-path "$WORK/adapter2.sock" \
        --ca-file ca.crt --bootstrap-key adapter2-rsa.key --name adapter2 \
        --tun-if tun0 --node-addr "$VM_LAN_IP:5000" --zpr-addr fd5a:5052:8888::2:1 \
        >adapter2.log 2>&1 &
    echo $! >> "$WORK/pids"
    sleep 2

    # The HTTP service behind adapter2 that adapter1 fetches from.
    ip netns exec zpr-a2 python3 -m http.server 8080 \
        --bind fd5a:5052:8888::2:1 --directory "$WORK/www" >http.log 2>&1 &
    echo $! >> "$WORK/pids"

    echo
    echo "Linux side up. Link state (NOT Active until ph.exe node runs on the VM):"
    "$PHCLI_BIN" -p "$WORK/vs-adapter.sock" link show || true
    "$PHCLI_BIN" -p "$WORK/adapter1.sock" link show || true
    "$PHCLI_BIN" -p "$WORK/adapter2.sock" link show || true
    echo
    echo "next: start ph.exe node on the VM (windows-node-test.md section 2)."
}

# ---------------------------------------------------------------------------
# nat-up / nat-down: forwarding + MASQUERADE for the namespace subnets, so
# the adapters (10.0.x.0/24, behind veths) can reach the node on the VM. Run
# on the HOST as root: the integration-test image has no iptables and its
# /proc/sys is read-only, and with --network host the container shares this
# network namespace anyway, so host rules cover it.
# ---------------------------------------------------------------------------
nat_up() {
    sysctl -qw net.ipv4.ip_forward=1
    iptables -t nat -A POSTROUTING -s 10.0.0.0/16 ! -d 10.0.0.0/16 -j MASQUERADE
    echo "forwarding on, MASQUERADE for 10.0.0.0/16 installed."
}

nat_down() {
    iptables -t nat -D POSTROUTING -s 10.0.0.0/16 ! -d 10.0.0.0/16 -j MASQUERADE 2>/dev/null || true
    echo "MASQUERADE for 10.0.0.0/16 removed (ip_forward left as-is)."
}

# ---------------------------------------------------------------------------
# down: kill what up started and remove the namespaces.
# ---------------------------------------------------------------------------
down() {
    if [ -f "$WORK/pids" ]; then
        # In reverse start order; a pid that already exited is fine.
        tac "$WORK/pids" | while read -r pid; do kill "$pid" 2>/dev/null || true; done
        rm -f "$WORK/pids"
    fi
    # Deleting a namespace deletes the interfaces inside it and its veth peer.
    ip netns del zpr-vs 2>/dev/null || true
    ip netns del zpr-a1 2>/dev/null || true
    ip netns del zpr-a2 2>/dev/null || true
    echo "Linux side down. \$WORK ($WORK) is left for inspection; remove it yourself."
    echo "(run 'nat-down' on the host to remove the MASQUERADE rule)"
}

case "${1:-}" in
    prepare)  prepare ;;
    nat-up)   nat_up ;;
    up)       up ;;
    down)     down ;;
    nat-down) nat_down ;;
    *) die "usage: $0 {prepare|nat-up|up|down|nat-down} (see integration-test/windows-node-test.md)" ;;
esac
