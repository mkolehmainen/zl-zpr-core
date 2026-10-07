# Windows adapter test

Hand-run, end-to-end verification that `ph adapter` on Windows carries real
traffic against a Linux node and visa service. There is no automated Windows
CI that carries real traffic, so run this whenever a change touches the Windows
datapath (Wintun, the named-pipe control channel, the `windows_unbatched`
engine, shutdown). It exercises: Wintun interface creation, docking over the substrate, `ph-cli`
over the named pipe, ICMPv6 and TCP through ZPR, and graceful Ctrl-C shutdown
that leaves no Wintun adapter behind. Section 6 (operator-run) checks who
may open the control pipe: a non-elevated `ph-cli` through the configured
`control_group`, with `ph` under a service identity and from an elevated
console (zipline#154).

Two machines:

* **Linux host** — runs the node, the visa service and one Linux adapter
  (`adapter1`), all inside the existing integration-test Docker image with
  `--network host`, so nothing needs to be installed on the host beyond Docker
  and the built binaries. The visa service and `adapter1` each run in their
  own network namespace inside the container (see 1b for why).
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
# Windows adapter test policy (integration-test/windows-adapter-test.md).

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

The node runs in the host network namespace, so the VM reaches it at
`$HOST_LAN_IP:5000`. The visa service (with its valkey and adapter) and
`adapter1` each get their own network namespace, joined to the host by a
veth pair, the same layout `lib/common_funcs.sh` builds for the
integration tests. They cannot share the node's namespace: the node's
traffic to the visa service's ZPR address would then be delivered locally
with the wrong source address (the visa service rejects it: "zpr addr does
not match connection source"), and `ph adapter` refuses to start when
another interface already routes the ZPR prefix ("running two adapters on
one host is not supported").

```sh
cd "$WORK"

# Namespaces for the visa service and adapter1, each on a veth /24 to the
# host namespace, with a default route back so the node's advertised
# $HOST_LAN_IP is reachable from inside.
ip netns add zpr-vs; ip netns add zpr-a
ip -n zpr-vs link set lo up; ip -n zpr-a link set lo up
ip link add veth-zpr-vs type veth peer veth0 netns zpr-vs
ip link add veth-zpr-a type veth peer veth0 netns zpr-a
ip addr add 10.0.0.1/24 dev veth-zpr-vs; ip link set veth-zpr-vs up
ip addr add 10.0.1.1/24 dev veth-zpr-a;  ip link set veth-zpr-a up
ip -n zpr-vs addr add 10.0.0.2/24 dev veth0; ip -n zpr-vs link set veth0 up
ip -n zpr-a  addr add 10.0.1.2/24 dev veth0; ip -n zpr-a  link set veth0 up
ip -n zpr-vs route add default via 10.0.0.1
ip -n zpr-a  route add default via 10.0.1.1

# TUN interfaces. Pre-creating them (with the address already set) works
# around the known Linux TUN bug described in docs/SETUP.md — required
# whenever zpr_addr is specified.
ip tuntap add name tun-n mode tun multi_queue
ip link set tun-n mtu 1400 && ip link set tun-n up
ip addr add fd5a:5052::2 peer fd5a:5052::1 dev tun-n

ip -n zpr-vs tuntap add name tun0 mode tun multi_queue
ip -n zpr-vs link set tun0 mtu 1400 && ip -n zpr-vs link set tun0 up
ip -n zpr-vs addr add fd5a:5052::1 peer fd5a:5052::2 dev tun0

ip -n zpr-a tuntap add name tun0 mode tun multi_queue
ip -n zpr-a link set tun0 mtu 1400 && ip -n zpr-a link set tun0 up
ip -n zpr-a addr add fd5a:5052:8888::1:1 peer fd5a:5052::/32 dev tun0

mkdir -p /var/run/zpr

# Substitute your checkout paths (the workspace is mounted at its host path).
PH=<zl-zpr-core>/target/debug/ph
PHCLI=<zl-zpr-core>/target/debug/ph-cli
VS=<zl-zpr-visaservice>/target/debug/vs

ip netns exec zpr-vs valkey-server --save '' --appendonly no >valkey.log 2>&1 &
sleep 1

ip netns exec zpr-vs "$VS" -c vs-config.toml --clear-state windows-smoke.bin2 >vs.log 2>&1 &
sleep 2

"$PH" node -l all=INFO \
  --control-path "$WORK/node.sock" \
  --self-addr 0.0.0.0:5000 \
  --advertised-substrate-addr "$HOST_LAN_IP:5000" \
  --ca-file ca.crt --certificate-file node.crt --private-key-file node.key \
  --auth-private-key node-rsa-key.pem \
  --tun-if tun-n --zpr-addr fd5a:5052::2 >node.log 2>&1 &
sleep 2

ip netns exec zpr-vs "$PH" adapter -l all=INFO \
  --control-path "$WORK/vs-adapter.sock" \
  --ca-file ca.crt --certificate-file vs.zpr.crt --private-key-file vs.zpr.key \
  --bootstrap-key actorvs-rsa.key \
  --tun-if tun0 --node-addr 10.0.0.1:5000 --zpr-addr fd5a:5052::1 \
  >vs-adapter.log 2>&1 &
sleep 5

ip netns exec zpr-a "$PH" adapter -l all=INFO \
  --control-path "$WORK/adapter1.sock" \
  --ca-file ca.crt --bootstrap-key adapter1-rsa.key --name adapter1 \
  --tun-if tun0 --node-addr 10.0.1.1:5000 --zpr-addr fd5a:5052:8888::1:1 \
  >adapter1.log 2>&1 &
sleep 5

# The HTTP service the Windows adapter will fetch from.
ip netns exec zpr-a python3 -m http.server 8080 --bind fd5a:5052:8888::1:1 >http.log 2>&1 &

# Sanity: adapter1 docked and its link is up. (The control socket is a
# filesystem path, so ph-cli needs no netns.)
"$PHCLI" -p "$WORK/adapter1.sock" link show
```

Expect `link show` to report one link `(Active)`. If not, read
`adapter1.log`, `vs-adapter.log` and `node.log`.

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

Expected startup: `WinTun: Creating adapter` in the log (plus `Removed
orphaned adapter` if a previous run was hard-killed), `Using packet I/O
engine windows_unbatched`, then `dock link granted ZPR addresses
[... fd5a:5052:8888::4:1 ...], becoming ACTIVE`. Repeated `Packet dropped
becuase TTL reached 0` lines are the OS's hop-limit-1 multicast (neighbour
discovery and the like) and are expected; the Linux adapters log them too. The console keeps
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

* `link show` reports the dock link `(Active)`; `counters` answers over
  the pipe (numbers are non-zero after the pings).
* `ping -6` gets replies from `fd5a:5052:8888::1:1` (0% loss).
* The HTTP fetch returns the `http.server` directory listing.

Optionally verify the reverse direction from the Linux container:
`ip netns exec zpr-a ping -6 -c 4 fd5a:5052:8888::4:1` (allowed by `allow A1
to access WPing`). Windows puts the `zpr` adapter on the Public network
profile, where Windows Defender Firewall drops inbound ICMPv6 echo requests,
so this fails until you allow them on that interface. ZPR has delivered the
packets by then: the `Inbound Packets Sent` counter in `ph-cli counters`
still rises.

```powershell
New-NetFirewallRule -DisplayName zpr-smoke-icmpv6 -Direction Inbound `
  -Protocol ICMPv6 -IcmpType 128 -InterfaceAlias zpr -Action Allow
# ... ping from Linux ...
Remove-NetFirewallRule -DisplayName zpr-smoke-icmpv6
```

## 4. Graceful shutdown

In the **first** PowerShell (the one running `ph.exe`), press **Ctrl-C**
once. Expect a graceful shutdown log ("attempting graceful shutdown") and the
process exiting on its own. Then verify the Wintun adapter is gone:

```powershell
Get-NetAdapter -Name zpr        # expect: no matching adapter / error
```

A leftover `zpr` adapter here is a failure (the delete-on-exit path in
`sys/windows/zprtun.rs` did not run). Note: after a hard kill (not Ctrl-C) a
stale adapter is expected (Windows names it `zpr 1`, so check `Get-NetAdapter`
without `-Name`) and is reaped by the next `ph.exe` startup (`Removed
orphaned adapter "zpr 1"`).

## 5. Teardown (Linux)

In the container shell: `kill %1 %2 %3 %4 %5 %6`. Host networking means the
node's TUN and the veth pairs live in the host namespace, so remove them
explicitly before leaving (deleting a namespace deletes the interfaces inside
it and its veth peer):

```sh
ip netns del zpr-vs; ip netns del zpr-a; ip link del tun-n
exit
rm -rf "$WORK"
```

## 6. Control pipe access for non-elevated `ph-cli` (zipline#154) — operator-run

**Operator-run.** This section needs a Windows VM; nothing on the Linux
build host runs it, and the unit gate only *compiles* the Windows-only
tests (`cargo xwin check --tests`). It checks the control pipe's DACL from
`docs/SETUP.md` ("Control pipe access and non-elevated `ph-cli`") in the
two launch modes that matter: `ph` under a service identity (SYSTEM, via
`psexec -s`), and `ph` from an elevated console. Run it before merging a
change to `sys/windows/control.rs`, `sys/control_access.rs`, or
`admin_api::local_group_sid`.

The issue text says `ph-cli status`; `ph-cli` has no `status` subcommand,
so the checks use `link show`, the same round-trip as 3a. A denied open
surfaces as `ph-cli`'s "no live packet handler socket (tried … and …)"
error, because both candidate pipes refuse it; `-p \\.\pipe\zpr-control`
shows the raw `Access is denied` instead.

### 6a. One-time setup (elevated PowerShell)

Keep the Linux side from section 1 up (run this section before section 5's
teardown), so `ph.exe` docks as in section 2.
Then create the group and two local test users (the passwords are
throwaway; this VM is a test box):

```powershell
net localgroup zipline /add
net user zpr-member  'Smoke-154-a!' /add
net user zpr-outside 'Smoke-154-b!' /add
net localgroup zipline zpr-member /add
# Windows unit tests that only compile on the build host — run them here:
cargo test -p admin-api local_group
```

Expected: the three `local_group` tests pass (`Users` resolves to
`S-1-5-32-545`, a random name is `None`, `SYSTEM` is `None`).

Membership is read at logon. `runas` starts a fresh logon, so it always
sees the current membership; an interactive session of a user added to the
group must log off and on first (the re-logon caveat in `docs/SETUP.md`).

### 6b. `ph` under a service identity (operator-run)

Stop any `ph.exe` from section 2 first (Ctrl-C). From an elevated
PowerShell, with [PsExec](https://learn.microsoft.com/sysinternals/downloads/psexec):

```powershell
cd C:\zpr-smoke
psexec -s -w C:\zpr-smoke C:\zpr-smoke\ph.exe adapter -c adapter.toml --control-group zipline
```

Expected startup line, in addition to section 2's:
`control pipe: granting local group 'zipline' (S-1-5-21-…) access`.

Then, from the **non-elevated** desktop session (or `runas`):

```powershell
# Member: succeeds.
runas /user:zpr-member  "cmd /k C:\zpr-smoke\ph-cli.exe link show"
# Non-member: denied.
runas /user:zpr-outside "cmd /k C:\zpr-smoke\ph-cli.exe link show"
# Your own admin account, NOT elevated, not in the group: denied
# (an unelevated admin token holds Administrators deny-only).
C:\zpr-smoke\ph-cli.exe link show
```

Pass criteria (each one operator-run):

* [ ] **6b-1** `zpr-member`, not elevated: `link show` reports the dock link.
* [ ] **6b-2** `zpr-outside`: denied (the "no live packet handler socket"
  error, or `Access is denied` with `-p \\.\pipe\zpr-control`).
* [ ] **6b-3** Your admin account, not elevated, not a member: denied.
* [ ] **6b-4** `net localgroup zipline <your account> /add`, log off and on,
  repeat 6b-3: now succeeds.

Ctrl-C does not reach a `psexec -s` process; stop it with
`taskkill /im ph.exe /f` (the next start reaps the stale Wintun adapter,
see section 4).

### 6c. `ph` from an elevated console (operator-run)

```powershell
cd C:\zpr-smoke
.\ph.exe adapter -c adapter.toml --control-group zipline
```

* [ ] **6c-1** Same user, **not elevated** (a normal PowerShell as the
  account that started `ph`): `.\ph-cli.exe link show` succeeds through the
  owner-SID ACE, without group membership. (Remove yourself from the group
  first if 6b-4 added you, and log off and on.)
* [ ] **6c-2** `runas /user:zpr-member "cmd /k C:\zpr-smoke\ph-cli.exe link show"`:
  succeeds through the group ACE (the over-the-shoulder case).
* [ ] **6c-3** `runas /user:zpr-outside "cmd /k C:\zpr-smoke\ph-cli.exe link show"`:
  denied.

### 6d. Group configured but missing (operator-run)

```powershell
.\ph.exe adapter -c adapter.toml --control-group zpr-no-such-group
```

* [ ] **6d-1** One warning at startup:
  `control group 'zpr-no-such-group' not found on this host; the control channel keeps its default access`.
  `ph` keeps running, and an elevated `ph-cli link show` still works.

### 6e. Cleanup

```powershell
net user zpr-member /delete
net user zpr-outside /delete
net localgroup zipline /delete
```

## Recording the result

Paste the transcript of sections 2–4 (adapter startup lines, `ph-cli`
output, ping/HTTP output, shutdown, `Get-NetAdapter` after exit) on the PR
or issue the run verifies. For section 6, paste the ticked checklist with
each check's `ph-cli` output and the `ph` startup line for the group.
