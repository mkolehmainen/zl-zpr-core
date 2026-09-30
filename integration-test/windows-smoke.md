# Windows adapter smoke test

Hand-run, end-to-end verification that `ph adapter` on Windows carries real
traffic against a Linux node and visa service (umbrella zipline#126, plan Z1).
It exercises: Wintun interface creation, docking over the substrate, `ph-cli`
over the named pipe, ICMPv6 and TCP through ZPR, and graceful Ctrl-C shutdown
that leaves no Wintun adapter behind.

Two machines:

* **Linux host** — runs the node, the visa service and one Linux adapter
  (`adapter1`), all inside the existing integration-test Docker image with
  `--network host`, so nothing needs to be installed on the host beyond Docker
  and the built binaries.
* **Windows 11 VM** (or physical box) on the same network as the Linux host —
  runs `ph.exe adapter` from an elevated PowerShell. The VM must be able to
  reach the Linux host's LAN IP directly (bridged networking, or libvirt NAT
  where the host is reachable at the gateway address).

The keys and certificates come from `integration-test/pregen` and are
**test-only fixtures** — do not reuse them outside a private test network.

## Prerequisites

Linux host:

* Binaries built on the host: `make` at the `zl-zpr-core` root (gives
  `target/debug/ph`, `ph-cli`), plus `vs` and `vs-admin` from a sibling
  `zl-zpr-visaservice` checkout (`make` there) and `zplc` from a sibling
  `zl-zpr-compiler` checkout. The commands below reference them by relative
  path, same as the integration-test symlinks do.
* Docker running, caller in the `docker` group. Build the test image once:
  `make -C integration-test docker-image`.

Windows VM:

* `ph.exe` and `ph-cli.exe` built on the VM per the Windows build
  prerequisites (MSVC Build Tools, CMake, NASM, capnp — see `docs/SETUP.md`
  "Windows" in `zl-zpr-dev-context`, or the STEPS TO CHECK THIS section of
  zl-zpr-core PR #53):

  ```powershell
  cargo build -p ph
  cargo build -p ph-cli --no-default-features
  ```

* `wintun.dll` (x64) from <https://www.wintun.net> placed **in the same
  directory as `ph.exe`**. The DLL is loaded at runtime; without it `ph`
  exits at startup with a load error. `wintun.dll` is signed by WireGuard
  LLC; `ph.exe` itself is unsigned and runs fine from an elevated console
  (verified on a Win11 VM, zl-zpr-core#53 — no SmartScreen block).

## 1. Linux side up

All of this runs on the Linux host from the `zl-zpr-core` repository root.
Pick the working directory and the host LAN IP first — every file below is
generated from these two variables:

```sh
export HOST_LAN_IP=192.168.122.1      # the Linux host's IP as seen FROM THE VM
export WORK=$(mktemp -d /tmp/win-smoke.XXXX)
```

### 1a. Policy, grants, and configs

```sh
PREGEN=$PWD/integration-test/pregen

# Key material: CA, node, vs.zpr, adapter1 (Linux), adapterw (Windows).
cp "$PREGEN/ca-cert.pem"        "$WORK/ca.crt"
cp "$PREGEN/ca-key.pem"         "$WORK/ca.key"
cp "$PREGEN/node.key"           "$WORK/node.key"
cp "$PREGEN/node-cert.pem"      "$WORK/node.crt"
cp "$PREGEN/node-rsa-key.pem"   "$WORK/node-rsa-key.pem"
cp "$PREGEN/node-rsa-pubkey.pem" "$WORK/node-rsa-pubkey.pem"
cp "$PREGEN/actor1-rsa.key"     "$WORK/adapter1-rsa.key"
cp "$PREGEN/actor1.pem"         "$WORK/adapter1.pem"
cp "$PREGEN/actor2-rsa.key"     "$WORK/adapterw-rsa.key"   # goes to the VM
cp "$PREGEN/actor2.pem"         "$WORK/adapterw.pem"
cp "$PREGEN/actorvs-rsa.key"    "$WORK/actorvs-rsa.key"

# Noise cert for the visa-service adapter (CN must be vs.zpr).
integration-test/lib/zpr-pki genkey > "$WORK/vs.zpr.key"
integration-test/lib/zpr-pki pubkey < "$WORK/vs.zpr.key" > "$WORK/vs.zpr.pubkey"
integration-test/lib/zpr-pki gensignedcert "$WORK/ca.crt" "$WORK/ca.key" \
  /CN=vs.zpr 1 < "$WORK/vs.zpr.pubkey" > "$WORK/vs.zpr.crt"

# The policy: one node, adapter1 (Linux) serves ping + HTTP :8080 to the
# Windows adapter; the Windows adapter serves ping back.
cat > "$WORK/windows-smoke.zpl" <<'EOF'
# Windows smoke-test policy (integration-test/windows-smoke.md).

define adapter as a device with zpr.adapter.cn.

define A1 as adapter with zpr.adapter.cn:adapter1.
define W as adapter with zpr.adapter.cn:adapterw.

define A1Ping as a service with device.zpr.adapter.cn:adapter1.
define A1Web as a service with device.zpr.adapter.cn:adapter1.
define WPing as a service with device.zpr.adapter.cn:adapterw.

allow W to access A1Ping.
allow W to access A1Web.
allow A1 to access WPing.

# Admin access to VS
define VsAdmin as a device with zpr.adapter.cn:'client.zpr.org'.
allow VsAdmin to access VisaService.
EOF

cat > "$WORK/windows-smoke.zplc" <<EOF
# -*- mode: toml -*-

[resolver]
order = ["hosts", "dns"]

[resolver.hosts]
"n0.zpr" = "fd5a:5052::2"
"n0.overlay" = "$HOST_LAN_IP"

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
"adapterw" = "adapterw.pem"

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

[services.A1Web]
protocol = "http"
provider = [["device.zpr.adapter.cn", "adapter1"]]

[services.WPing]
protocol = "ping"
provider = [["device.zpr.adapter.cn", "adapterw"]]
EOF

# actorvs.pem is referenced by the [bootstrap] table above.
cp "$PREGEN/actorvs.pem" "$WORK/actorvs.pem"

# Address grants for the two adapters.
cat > "$WORK/addresses.json" <<'EOF'
{
  "device.zpr.adapter.cn": {
    "adapter1": { "zpr_addr": ["fd5a:5052:8888::1:1"] },
    "adapterw": { "zpr_addr": ["fd5a:5052:8888::4:1"] }
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

# Compile the policy.
../zl-zpr-compiler/target/debug/zplc -c "$WORK/windows-smoke.zplc" \
  -d "$WORK" "$WORK/windows-smoke.zpl"
```

`zplc` prints the output file name; expect `$WORK/windows-smoke.bin2`.

### 1b. Node, visa service, Linux adapter

Run the whole Linux side inside the integration-test container with host
networking, so the node's dock port is reachable from the VM and no valkey
install is needed on the host:

```sh
docker run --rm -it --privileged --network host \
  -e HOST_LAN_IP -v "$(realpath ..)":"$(realpath ..)" -v "$WORK":"$WORK" -e WORK \
  -w "$PWD" zpr-integration-test bash
```

Everything below runs in that container shell (root, host network).

```sh
cd "$WORK"

# TUN interfaces. Pre-creating them (with the address already set) works
# around the known Linux TUN bug described in docs/SETUP.md — required
# whenever zpr_addr is specified.
ip tuntap add name tun-n mode tun multi_queue
ip link set tun-n mtu 1400 && ip link set tun-n up
ip addr add fd5a:5052::2 peer fd5a:5052::1 dev tun-n

ip tuntap add name tun-v mode tun multi_queue
ip link set tun-v mtu 1400 && ip link set tun-v up
ip addr add fd5a:5052::1 peer fd5a:5052::2 dev tun-v

ip tuntap add name tun-a1 mode tun multi_queue
ip link set tun-a1 mtu 1400 && ip link set tun-a1 up
ip addr add fd5a:5052:8888::1:1 peer fd5a:5052::/32 dev tun-a1

mkdir -p /var/run/zpr

# Substitute your checkout paths (the workspace is mounted at its host path).
PH=<zl-zpr-core>/target/debug/ph
PHCLI=<zl-zpr-core>/target/debug/ph-cli
VS=<zl-zpr-visaservice>/target/debug/vs

valkey-server --save '' --appendonly no >valkey.log 2>&1 &

"$VS" -c vs-config.toml --clear-state windows-smoke.bin2 >vs.log 2>&1 &
sleep 2

"$PH" node -l all=INFO \
  --control-path "$WORK/node.sock" --capture-path "$WORK/node-cap.sock" \
  --self-addr 0.0.0.0:5000 \
  --advertised-substrate-addr "$HOST_LAN_IP:5000" \
  --ca-file ca.crt --certificate-file node.crt --private-key-file node.key \
  --auth-private-key node-rsa-key.pem \
  --tun-if tun-n --zpr-addr fd5a:5052::2 >node.log 2>&1 &
sleep 2

"$PH" adapter -l all=INFO \
  --control-path "$WORK/vs-adapter.sock" --capture-path "$WORK/vs-adapter-cap.sock" \
  --ca-file ca.crt --certificate-file vs.zpr.crt --private-key-file vs.zpr.key \
  --bootstrap-key actorvs-rsa.key \
  --tun-if tun-v --node-addr 127.0.0.1:5000 --zpr-addr fd5a:5052::1 \
  >vs-adapter.log 2>&1 &
sleep 3

"$PH" adapter -l all=INFO \
  --control-path "$WORK/adapter1.sock" --capture-path "$WORK/adapter1-cap.sock" \
  --ca-file ca.crt --bootstrap-key adapter1-rsa.key --name adapter1 \
  --tun-if tun-a1 --node-addr 127.0.0.1:5000 --zpr-addr fd5a:5052:8888::1:1 \
  >adapter1.log 2>&1 &
sleep 3

# The HTTP service the Windows adapter will fetch from.
python3 -m http.server 8080 --bind fd5a:5052:8888::1:1 >http.log 2>&1 &

# Sanity: adapter1 docked and its link is up.
"$PHCLI" -p "$WORK/adapter1.sock" link show
```

Expect `link show` to report link 1 up/authenticated. If not, read
`adapter1.log` and `node.log`.

## 2. Windows side

Copy to a directory on the VM (e.g. `C:\zpr-smoke`):

* `ph.exe`, `ph-cli.exe`, `wintun.dll` (all three in the same directory),
* from the Linux host: `$WORK/ca.crt` and `$WORK/adapterw-rsa.key`.

Create `C:\zpr-smoke\adapter.toml` (replace the IP with your
`$HOST_LAN_IP`):

```toml
[global]
ca_file = 'ca.crt'
zpr_addr = [ "fd5a:5052:8888::4:1" ]
tun_if = "zpr"

[adapter]
name = "adapterw"
node_addr = "192.168.122.1:5000"
bootstrap_key = 'adapterw-rsa.key'
```

From an **elevated** PowerShell (Run as administrator — Wintun device
creation requires it):

```powershell
cd C:\zpr-smoke
.\ph.exe adapter -c adapter.toml
```

Expected startup: a `Wintun adapter 'zpr'` line in the log, the address and
route applied via `netsh`, then a docked link to the node. The console keeps
running; leave it and open a **second elevated PowerShell** for the checks.

## 3. Checks (second elevated PowerShell)

```powershell
cd C:\zpr-smoke

# 3a. ph-cli over the named pipe (\\.\pipe\zpr-control-<your SID>).
.\ph-cli.exe link show
.\ph-cli.exe counters

# 3b. The Wintun adapter exists.
Get-NetAdapter -Name zpr

# 3c. ICMPv6 through ZPR to the Linux adapter.
ping -6 -n 4 fd5a:5052:8888::1:1

# 3d. TCP through ZPR: HTTP fetch from the Linux adapter's service.
curl.exe -6 -sS "http://[fd5a:5052:8888::1:1]:8080/" | Select-Object -First 5
```

Pass criteria:

* `link show` reports the link up and authenticated; `counters` answers over
  the pipe (numbers are non-zero after the pings).
* `ping -6` gets replies from `fd5a:5052:8888::1:1` (0% loss).
* The HTTP fetch returns the `http.server` directory listing.

Optionally verify the reverse direction from the Linux container:
`ping -6 -c 4 fd5a:5052:8888::4:1` (allowed by `allow A1 to access WPing`).

## 4. Graceful shutdown

In the **first** PowerShell (the one running `ph.exe`), press **Ctrl-C**
once. Expect a graceful shutdown log ("attempting graceful shutdown") and the
process exiting on its own. Then verify the Wintun adapter is gone:

```powershell
Get-NetAdapter -Name zpr        # expect: no matching adapter / error
```

A leftover `zpr` adapter here is a failure (the delete-on-exit path in
`sys/windows/zprtun.rs` did not run). Note: after a hard kill (not Ctrl-C) a
stale adapter is expected and is reaped by the next `ph.exe` startup.

## 5. Teardown (Linux)

In the container shell: `kill %1 %2 %3 %4 %5 %6` (or just exit the container
— host networking means the TUNs must be removed explicitly):

```sh
ip link del tun-n; ip link del tun-v; ip link del tun-a1
exit
rm -rf "$WORK"
```

## Recording the result

Paste the transcript of sections 2–4 (adapter startup lines, `ph-cli`
output, ping/HTTP output, shutdown, `Get-NetAdapter` after exit) on the
Windows umbrella issue (zipline#126).
