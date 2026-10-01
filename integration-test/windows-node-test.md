# Windows node test

Hand-run, end-to-end verification that `ph node` on Windows carries real
traffic between Linux adapters and hosts the visa service's support service
(VSS). This is the role-inverted twin of `windows-adapter-test.md`: there the
Windows VM was an adapter docked to a Linux node; here the **Windows VM is the
node** and everything else — valkey, the visa service, the visa service's
adapter, and two client adapters — runs on the Linux host. There is no
automated Windows CI that carries real traffic, so run this whenever a change
touches the Windows node path (node self-addressing through `TunCtl`
(zipline#159), the substrate socket (zipline#160), the VSS bind, forwarding
through the `windows_unbatched` engine, shutdown).

It exercises: Wintun interface creation and node self-addressing (address +
visa-service /128 route via `netsh`), the dock listener on a concrete
`self_addr`, the VSS TCP listener on the node's ZPR address, visa issuance
through the node, adapter-to-adapter traffic forwarded by the Windows node,
and graceful Ctrl-C shutdown that leaves no Wintun adapter behind.

Two machines:

* **Windows 11 VM** (or physical box) — runs `ph.exe node` from an elevated
  PowerShell. The Linux host must be able to reach the VM's LAN IP directly
  (bridged networking, or libvirt NAT where the VM is reachable from the
  host).
* **Linux host** — runs valkey, the visa service, the visa service's adapter
  and two client adapters (`adapter1`, `adapter2`), all inside the existing
  integration-test Docker image with `--network host`. Each `ph adapter` gets
  its own network namespace because running two adapters in one namespace is
  unsupported (the second refuses activation: "already routes to interface").
  `integration-test/windows-node-linux-host.sh` scripts this whole side; the
  layout it builds is described in "Linux-side layout" below.

The keys and certificates come from `integration-test/pregen` and are
**test-only fixtures** — do not reuse them outside a private test network.

Topology, all through the Windows node:

```
   Linux host (docker, host network)                 Windows VM
  ┌────────────────────────────────────┐          ┌───────────────────┐
  │ netns zpr-vs: valkey, vs,          │   UDP    │ ph.exe node       │
  │   vs-adapter  (fd5a:5052::1) ──────┼──:5000──▶│  self_addr        │
  │ netns zpr-a1: adapter1             │          │  <VM LAN IP>:5000 │
  │   (fd5a:5052:8888::1:1) ───────────┼──:5000──▶│  zpr-addr         │
  │ netns zpr-a2: adapter2 + http:8080 │          │  fd5a:5052::2     │
  │   (fd5a:5052:8888::2:1) ───────────┼──:5000──▶│  VSS :8183        │
  └────────────────────────────────────┘          └───────────────────┘
```

The traffic step is `adapter1` fetching from an HTTP server behind
`adapter2`: every data packet crosses the VM's single unbatched substrate
socket twice (in from `adapter1`, out to `adapter2`).

## Prerequisites

Linux host:

* Binaries built on the host: `make` at the `zl-zpr-core` root (gives
  `target/debug/ph`, `ph-cli`), plus `vs` from a sibling `zl-zpr-visaservice`
  checkout (`make` there) and `zplc` from a sibling `zl-zpr-compiler`
  checkout. The helper script finds them at those sibling paths; override
  with `PH_BIN` / `PHCLI_BIN` / `VS_BIN` / `ZPLC_BIN`.
* Docker running, caller in the `docker` group. Build the test image once:
  `make -C integration-test docker-image`.

Windows VM:

* `ph.exe` and `ph-cli.exe` built on the VM, and `wintun.dll` placed next to
  `ph.exe` — exactly as in `windows-adapter-test.md` "Prerequisites, Windows
  VM" (build commands, DLL source and signing notes are there; they are
  identical for the node role).

## 1. Linux side up

From the `zl-zpr-core` repository root on the Linux host. Everything is
driven by two variables: the VM's LAN IP as seen from the Linux host, and a
scratch directory.

```sh
export VM_LAN_IP=192.168.122.188     # the Windows VM's IP as seen FROM THE LINUX HOST
export WORK=$(mktemp -d /tmp/win-node.XXXX)

# Generate keys, configs, policy; compiles the policy with zplc.
integration-test/windows-node-linux-host.sh prepare

# Forwarding + NAT so the namespaced adapters can reach the VM — on the
# HOST, as root (the integration-test image has no iptables and a read-only
# /proc/sys; with --network host the rules cover the container anyway).
sudo -E integration-test/windows-node-linux-host.sh nat-up

# Enter the integration-test container (host network; the capabilities and
# the apparmor opt-out are what `ip netns` and TUN creation need — narrower
# than the adapter test's --privileged, which some setups block).
docker run --rm -it --network host \
  --cap-add=NET_ADMIN --cap-add=SYS_ADMIN --cap-add=NET_RAW \
  --security-opt apparmor=unconfined --device /dev/net/tun \
  -e VM_LAN_IP -v "$(realpath ..)":"$(realpath ..)" -v "$WORK":"$WORK" -e WORK \
  -w "$PWD" zpr-integration-test bash

# Inside the container: namespaces, valkey, vs, vs-adapter, adapter1,
# adapter2, and the HTTP server behind adapter2.
integration-test/windows-node-linux-host.sh up
```

`up` ends by printing `ph-cli link show` for each adapter. **No link is
`Active` yet** — the node does not exist until section 2 — and that is
expected: the adapters keep retrying their dock in the background and go
`Active` on their own once the node is up. If a `ph` or `vs` process exited
instead, read its log in `$WORK` before moving on.

### Linux-side layout (what the script builds)

For auditing; the script is the executable form of this list.

* Three namespaces: `zpr-vs` (valkey, `vs`, the vs adapter), `zpr-a1`
  (`adapter1`), `zpr-a2` (`adapter2` + `python3 -m http.server 8080` bound to
  `adapter2`'s ZPR address, serving `$WORK/www` which contains a 64 MiB
  `blob` for the throughput number). Each namespace joins the host over a
  veth /24 (`10.0.0.x`, `10.0.1.x`, `10.0.2.x`) with a default route to the
  host side, the same shape as `windows-adapter-test.md` 1b.
* Unlike the adapter test, the node the adapters dock to is **not** on this
  host, so the namespaces need a route to the VM: `nat-up` (run on the host,
  as root) enables `net.ipv4.ip_forward` and adds one `MASQUERADE` rule for
  `10.0.0.0/16` (`nat-down` removes it). The VM therefore sees all three
  adapters as the Linux host's LAN IP on distinct UDP source ports, which the
  dock does not care about. (Alternative, if you prefer no NAT: add a route
  on the VM for `10.0.0.0/16` via the Linux host's LAN IP and skip the
  MASQUERADE.)
* TUN devices are pre-created with their address already set, working around
  the Linux TUN bug described in `docs/SETUP.md` (required whenever
  `zpr_addr` is given): `fd5a:5052::1` for the vs adapter,
  `fd5a:5052:8888::1:1` / `::2:1` for `adapter1` / `adapter2`.
* Policy (`$WORK/windows-node.zpl` + `.zplc`): the node is the VM
  (`substrate_addrs.in1 = "<VM LAN IP>:5000"`, ZPR address `fd5a:5052::2`);
  services `A2Web` (TCP 8080) and `A2Ping` behind `adapter2`, `A1Ping`
  behind `adapter1`; `allow A1 to access A2Web / A2Ping`, `allow A2 to
  access A1Ping`. Static ZPR addresses come from the `addresses` file store
  exactly as in the adapter test.
* Identities: `actor1` → `adapter1`, `actor2` → `adapter2`, `actorvs` + a
  generated `vs.zpr` noise certificate for the vs adapter; the node's key
  material (`node.key`, `node.crt`, `node-rsa-key.pem`) is staged in
  `$WORK/vm/` for copying to the VM.

## 2. Windows side

Copy to a directory on the VM (e.g. `C:\zpr-node`):

* `ph.exe`, `ph-cli.exe`, `wintun.dll` (all three in the same directory),
* from the Linux host, the staged node material: `$WORK/vm/ca.crt`,
  `$WORK/vm/node.crt`, `$WORK/vm/node.key`, `$WORK/vm/node-rsa-key.pem`.

Firewall first. Two rules are *expected* to be necessary — the dock listener
(UDP 5000 on the LAN interface) and the VSS listener (TCP 8183, reached over
the Wintun interface, which Windows places on the Public profile where
unsolicited inbound is dropped):

```powershell
New-NetFirewallRule -DisplayName zpr-node-dock -Direction Inbound `
  -Protocol UDP -LocalPort 5000 -Action Allow
New-NetFirewallRule -DisplayName zpr-node-vss -Direction Inbound `
  -Protocol TCP -LocalPort 8183 -InterfaceAlias zpr-node -Action Allow
```

Checklist item 3 asks which rules are *actually* required: on the first run,
add no rules, watch what fails (no dock → UDP rule; dock up but the visa
service never registers → VSS rule), add them one at a time and record the
result. On later runs just add both up front.

Start the node from an **elevated** PowerShell (Wintun device creation
requires it). The concrete `--self-addr` is decision N1 of the win-node plan:
the Windows engine rejects a wildcard bind by design, and with a concrete
address no separate `advertised_substrate_addr` is needed (it defaults to
`self_addr` when that is specific).

```powershell
cd C:\zpr-node
.\ph.exe node -l all=INFO `
  --self-addr <VM LAN IP>:5000 `
  --tun-if zpr-node --zpr-addr fd5a:5052::2 `
  --ca-file ca.crt --certificate-file node.crt --private-key-file node.key `
  --auth-private-key node-rsa-key.pem
```

Expected startup, in order:

* `WinTun: Creating adapter` (plus `Removed orphaned adapter` after a
  previous hard kill);
* `applying node ZPR address fd5a:5052::2/32 to the TUN device` — the node
  self-addresses via `netsh` (zipline#159) — and the visa-service host-route
  install that follows it (`fd5a:5052::1/128` on `zpr-node`; `netsh
  interface ipv6 show route` confirms);
* `advertising substrate address <VM LAN IP>:5000 to the visa service`;
* `Using packet I/O engine windows_unbatched`;
* within ~30 s of the Linux side being up: the vs adapter's dock completing
  and the visa-service connection registering (the Linux-side `vs.log` shows
  the VSS registration; the adapters go `Active`).

Leave the console running and open a **second elevated PowerShell** for the
checks.

## 3. Checks

On the VM (second elevated PowerShell):

```powershell
cd C:\zpr-node
.\ph-cli.exe link show        # expect THREE links (vs adapter, adapter1, adapter2), all (Active)
.\ph-cli.exe counters
Get-NetAdapter -Name zpr-node # the Wintun adapter exists; note its reported Status
```

On the Linux host (container shell):

```sh
# Dock state from each adapter's side: one link, (Active).
target/debug/ph-cli -p "$WORK/adapter1.sock" link show
target/debug/ph-cli -p "$WORK/adapter2.sock" link show

# ICMPv6 through ZPR, adapter1 -> adapter2, forwarded by the Windows node.
ip netns exec zpr-a1 ping -6 -c 4 fd5a:5052:8888::2:1

# The traffic step: HTTP through ZPR, adapter1 fetches from behind adapter2.
ip netns exec zpr-a1 curl -6 -sS "http://[fd5a:5052:8888::2:1]:8080/" | head -5

# Numbers for checklist item 4 (>=2 adapters, one unbatched socket) — record
# both results verbatim in Findings; do NOT tune anything:
ip netns exec zpr-a1 ping -6 -c 500 -i 0.02 -q fd5a:5052:8888::2:1   # record the loss %
ip netns exec zpr-a1 curl -6 -sS -o /dev/null \
  -w 'speed_download=%{speed_download} bytes/s\n' \
  "http://[fd5a:5052:8888::2:1]:8080/blob"                           # record the rate
```

Pass criteria:

* VM `link show` reports three links `(Active)`; `counters` answers over the
  named pipe (non-zero after the pings).
* `ping -6` from `zpr-a1` gets replies from `fd5a:5052:8888::2:1` (0% loss on
  the 4-packet check).
* The HTTP fetch returns the `http.server` directory listing, and the `blob`
  fetch completes (its rate and the flood-ping loss are recorded, whatever
  they are — the numbers are findings, not gates).

## 4. Checklist — the unknowns this run settles

These are the six open questions from zipline#162. Record each one in
**Findings** as PASS / FAIL / N-A plus a line of evidence; a FAIL becomes
either a small fix in the same PR (with a unit test) or a filed zipline
issue whose number goes in Findings.

1. **Duplicate-address detection / tentative bind.** Does the VSS bind (the
   `vss_addr` listener on `fd5a:5052::2:8183`, `adapter/ph/src/main.rs`,
   `launch_vss` call) fail at startup because the freshly `netsh`-added
   address is still tentative? Evidence: `VSS server terminated` /
   bind-error lines in the node console right after the self-addressing
   lines. If it fails, the fix is a bounded wait for the address to leave
   the tentative state (the Windows arm of the zipline#159 helper), not a
   sleep.
   `[ ] PASS / [ ] FAIL: ______________________________________________`
2. **On-link reachability of `fd5a:5052::1`** with the `/128` route
   installed at startup. Evidence: `netsh interface ipv6 show route` lists
   `fd5a:5052::1/128` on `zpr-node`, and the visa service registers (visas
   are issued; adapters go Active).
   `[ ] PASS / [ ] FAIL: ______________________________________________`
3. **Which firewall rules are actually required.** Evidence: the
   add-one-at-a-time procedure from section 2; list the final required set.
   `[ ] UDP 5000 required?  [ ] TCP 8183 required?  Other: ______________`
4. **Two or more adapters docked through one unbatched socket.** Evidence:
   the flood-ping loss % and the `blob` download rate from section 3,
   recorded verbatim. Numbers only — no tuning in this task.
   `loss: ________ %   rate: ________ bytes/s`
5. **`set_carrier` is a NOP on Windows.** The node calls "carrier ON" at
   startup (`tun_ctl.set_carrier`, node arm of `main.rs`); on Windows this
   does nothing. Evidence: no carrier-related error in the node console, and
   `Get-NetAdapter -Name zpr-node` reports the adapter usable (record the
   Status it shows) — i.e. the NOP has no visible effect, good or bad.
   `[ ] PASS / [ ] FAIL: Status reported: _____________________________`
6. **Shutdown.** Ctrl-C in the node console: graceful-shutdown log lines,
   process exits on its own, `Get-NetAdapter -Name zpr-node` then reports no
   adapter, and the Linux adapters log the dock link going down
   (`disconnect_adapters` ran — see each `adapter*.log`). Then start
   `ph.exe node` a second time with the same command line: it must come up
   without "held by another process" or an orphaned-adapter error.
   `[ ] PASS / [ ] FAIL: ______________________________________________`

## 5. Teardown

VM: Ctrl-C already stopped the node (section 4, item 6); remove the firewall
rules:

```powershell
Remove-NetFirewallRule -DisplayName zpr-node-dock
Remove-NetFirewallRule -DisplayName zpr-node-vss
```

Linux (container shell): `integration-test/windows-node-linux-host.sh down`
kills the started processes and deletes the namespaces. Back on the host:
`sudo integration-test/windows-node-linux-host.sh nat-down` removes the
MASQUERADE rule. Then `rm -rf "$WORK"`.

## Recording the result

Paste the transcript (node startup lines, `ph-cli` output from both sides,
ping/HTTP/rate output, shutdown and the post-exit `Get-NetAdapter`) on the PR
or issue the run verifies, and fill in **Findings** below in the same PR.

## Findings

*(filled in by the first run; keep one dated subsection per run)*

### <YYYY-MM-DD> — first end-to-end run

* Build commit (`zl-zpr-core`): `________`
* Windows version / OS build (`winver`): `________`

| # | Checklist item | Result | Evidence / issue |
|---|---|---|---|
| 1 | tentative-address VSS bind | | |
| 2 | `fd5a:5052::1` on-link via /128 route | | |
| 3 | firewall rules actually required | | |
| 4 | ≥2 adapters, one socket (numbers) | | |
| 5 | `set_carrier` NOP, no visible effect | | |
| 6 | Ctrl-C teardown + clean second start | | |
