# macOS adapter test

Hand-run, end-to-end verification that `ph adapter` on macOS carries real
traffic against a Linux node and visa service. This is the adapter-role
inversion of `macos-node-test.md` (and the macOS sibling of
`windows-adapter-test.md`): the **Mac is an adapter**, docking to a node
that runs on the Linux host alongside valkey, the visa service, the visa
service's adapter and one Linux peer adapter. There is no automated macOS
CI that carries real traffic (master-plan decision M5), so run this
whenever a change touches the macOS adapter path (utun creation through
`TunCtl`, the dock-time `add_address`/`add_route` activation sequence, the
`posix_unbatched` engine, shutdown).

It exercises: utun interface creation (named and kernel-chosen), the
dock-time addressing sequence — `TunCtl::add_address` (an
`ifconfig <utun> inet6 <addr>/32 alias`) followed by
`TunCtl::add_route` for the ZPR internal network `fd5a:5052::/32` when the
link activates — docking over the substrate, visa issuance, ICMPv6 and TCP
through ZPR in both directions, `ph-cli` over the unix control socket, and
graceful Ctrl-C shutdown that leaves no stale utun state behind.

Two machines:

* **Mac** (Apple Silicon or Intel) — runs `ph adapter` under `sudo` from a
  terminal. The Mac must be able to reach the Linux host's LAN IP directly.
* **Linux host** — runs the node, the visa service and one Linux adapter
  (`adapter1`), all inside the existing integration-test Docker image with
  `--network host`. This side is **identical to `windows-adapter-test.md`
  section 1** — same policy shape, same namespaces, same commands — with
  the two substitutions in section 1 below (the Mac adapter's name and the
  pregen key routing).

The keys and certificates come from `integration-test/pregen` and are
**test-only fixtures** — do not reuse them outside a private test network.

Topology:

```
   Linux host (docker, host network)                Mac
  ┌────────────────────────────────────┐         ┌──────────────────────┐
  │ host netns: ph node                │   UDP   │ sudo ph adapter      │
  │   self_addr 0.0.0.0:5000           │◀──:5000─┤  dock to             │
  │   advertised $HOST_LAN_IP:5000     │         │  $HOST_LAN_IP:5000   │
  │   zpr-addr fd5a:5052::2            │         │  utun via TunCtl     │
  │ netns zpr-vs: valkey, vs,          │         │  zpr-addr            │
  │   vs-adapter  (fd5a:5052::1)       │         │  fd5a:5052:8888::4:1 │
  │ netns zpr-a: adapter1 + http:8080  │         └──────────────────────┘
  │   (fd5a:5052:8888::1:1)            │
  └────────────────────────────────────┘
```

The traffic steps are the Mac adapter pinging and fetching HTTP from
`adapter1` through the Linux node, and `adapter1` pinging back.

## Prerequisites

Linux host: exactly as in `windows-adapter-test.md` "Prerequisites, Linux
host" — `make` at the `zl-zpr-core` root, `vs` from a sibling
`zl-zpr-visaservice` checkout, `zplc` from a sibling `zl-zpr-compiler`
checkout, Docker with the `zpr-integration-test` image built
(`make -C integration-test docker-image`).

Mac:

* `ph` and `ph-cli` built on the Mac: `make` at the `zl-zpr-core`
  repository root (plain `cargo build -p ph -p ph-cli` works too). Nothing
  else — there is no wintun analogue; `utun` devices are in-kernel and `ph`
  creates them through a `PF_SYSTEM` control socket. Creation requires
  root, hence `sudo` below.
* If the Mac's application firewall is enabled (System Settings → Network →
  Firewall), the adapter's exposure differs from the node's: the adapter
  **originates** the dock (outbound UDP), so docking is expected to work
  even with the firewall on — the inbound-exposed piece is traffic arriving
  back through the established UDP flow and the ZPR-internal services the
  Mac answers (the ping back from `adapter1`). Whether the firewall
  interferes at all is checklist item 4; the node run never exercised it
  (firewall disabled on that Mac). As there, the command-line tool is
  `/usr/libexec/ApplicationFirewall/socketfilterfw`, and the expected fix,
  if one is needed, is to allow the binary **the test actually runs** — the
  copy in `~/zpr-adapter` that section 2 starts, not the build-tree
  `target/debug/ph` (the firewall keys rules on the executable's path):

  ```sh
  sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add ~/zpr-adapter/ph
  sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp ~/zpr-adapter/ph
  ```

  On the first run add nothing up front: watch what fails, apply the fix,
  and record the result in Findings.

## 1. Linux side up

Follow `windows-adapter-test.md` **section 1 verbatim** — sections 1a
(policy, grants, configs) and 1b (node, visa service, Linux adapter in the
container) — with two substitutions:

* `HOST_LAN_IP` is the Linux host's IP **as seen from the Mac** (not from
  a VM).
* The remote adapter is the Mac, not a Windows box. Where that document
  stages `actor2` material as `adapterw`, name it `adapterm` instead:

  ```sh
  cp "$PREGEN/actor2-rsa.key"  "$WORK/adapterm-rsa.key"   # goes to the Mac
  cp "$PREGEN/actor2.pem"      "$WORK/adapterm.pem"
  ```

  and carry the rename through the generated files: in the `.zpl`, define
  `M` (not `W`) as the adapter with `zpr.adapter.cn:adapterm` and name the
  services accordingly (`MPing` instead of `WPing`); in the `.zplc`
  `[bootstrap]` table, `"adapterm" = "adapterm.pem"`; in `addresses.json`,
  grant `adapterm` the address `fd5a:5052:8888::4:1`. Everything else —
  the vs.zpr noise cert, the namespaces, the TUN pre-creation, the service
  start order — is unchanged and not macOS-specific.

As in the node test, the Linux side being up does not make anything
`Active` yet — the vs-adapter and `adapter1` dock to the local node
immediately, so expect `"$PHCLI" -p "$WORK/adapter1.sock" link show` to
report one link `(Active)` before the Mac enters the picture.

## 2. Mac side

Copy from the Linux host to a working directory on the Mac (e.g.
`~/zpr-adapter`), next to the `ph` / `ph-cli` binaries or anywhere you
like:

* `$WORK/ca.crt` and `$WORK/adapterm-rsa.key`.

Create `~/zpr-adapter/adapter.toml` (replace the IP with your
`$HOST_LAN_IP`):

```toml
[global]
ca_file = 'ca.crt'
zpr_addr = [ "fd5a:5052:8888::4:1" ]
tun_if = "utun9"

[adapter]
name = "adapterm"
node_addr = "192.168.122.1:5000"
bootstrap_key = 'adapterm-rsa.key'
```

(`tun_if` on macOS must be of the form `utunN`; `utun9` is arbitrary but
high enough not to collide with the system's own utuns. Checklist item 2
also runs this **without** `tun_if` to confirm the kernel-chosen-name
path. Unlike the Linux adapter in the container, no TUN pre-creation is
needed or possible — `ph` creates the utun itself, which is exactly what
this test verifies.)

Start the adapter from a terminal:

```sh
cd ~/zpr-adapter
sudo ./ph adapter -l all=INFO -c adapter.toml
```

Expected startup, in order:

* utun creation (the device appears in `ifconfig` as `utun9`) — created
  **unaddressed**; unlike a node, an adapter does not self-address at
  startup, it is addressed when the dock link activates (zipline#161);
* `Using packet I/O engine posix_unbatched`;
* the dock completing: `dock link granted ZPR addresses
  [... fd5a:5052:8888::4:1 ...], becoming ACTIVE` — at which point the
  activation sequence applies the granted address via `TunCtl::add_address`
  (`ifconfig utun9 inet6 fd5a:5052:8888::4:1/32 alias`) and ensures the
  ZPR internal network route via `TunCtl::add_route`
  (`/sbin/route -n add -inet6 fd5a:5052::/32 -interface utun9`), checking
  first that no other interface already owns the route (zipline#101 — a
  second ZPR adapter on the host refuses to start);
* `WARN ... packet steering not supported on this OS` — expected on macOS.

Leave the adapter running and open a **second terminal** for the checks.

## 3. Checks

On the Mac (second terminal):

```sh
cd ~/zpr-adapter
# NOT under sudo: `sudo ph adapter` binds /var/run/zpr/<SUDO_UID>/control.sock
# owned by you, and `sudo ph-cli` (uid 0) would look in /var/run/zpr/0/.
./ph-cli link show             # expect ONE link (the dock), (Active)
./ph-cli counters
ifconfig utun9                 # carries fd5a:5052:8888::4:1 prefixlen 32
netstat -rn -f inet6 | grep -i 'fd5a:5052\|utun9'   # route shape — evidence for checklist item 1

# ICMPv6 through ZPR to the Linux adapter.
ping6 -c 4 fd5a:5052:8888::1:1

# TCP through ZPR: HTTP fetch from the Linux adapter's service.
curl -6 -sS "http://[fd5a:5052:8888::1:1]:8080/" | head -5

# Numbers for the record (findings, not gates): flood-ish ping and a bulk
# fetch. Generate the blob on the Linux side first if it is not there:
#   ip netns exec zpr-a dd if=/dev/urandom of=blob bs=1M count=64
ping6 -c 500 -i 0.02 fd5a:5052:8888::1:1 | tail -2
curl -6 -sS -o /dev/null -w '%{size_download} bytes  %{speed_download} bytes/s\n' \
  "http://[fd5a:5052:8888::1:1]:8080/blob"
```

On the Linux host (container shell): verify the reverse direction —
`ip netns exec zpr-a ping -6 -c 4 fd5a:5052:8888::4:1` (allowed by `allow
A1 to access MPing`). Whether the Mac's application firewall interferes
with the inbound echo through the utun is part of checklist item 4; if the
replies do not come back, check whether the `Inbound Packets Sent` counter
in the Mac's `ph-cli counters` still rises — then ZPR has delivered the
packets and the drop is local to the Mac.

Pass criteria:

* Mac `link show` reports the dock link `(Active)`; `counters` answers
  over the control socket (non-zero after the pings).
* `ping6` gets replies from `fd5a:5052:8888::1:1` (0% loss on the
  4-packet check).
* The HTTP fetch returns the `http.server` directory listing, and the
  `blob` fetch completes (its rate and the flood-ping loss are recorded,
  whatever they are — the numbers are findings, not gates).
* The reverse ping from `zpr-a` gets replies from `fd5a:5052:8888::4:1`,
  or the firewall interference is identified and recorded (item 4).

## 4. Checklist — the unknowns this run settles

Record each one in **Findings** as PASS / FAIL / N-A plus a line of
evidence; a FAIL becomes either a small fix in the same PR (with a unit
test) or a filed zipline issue whose number goes in Findings.

1. **Dock-time addressing and route shape.** The adapter activates with
   `add_address` (the `/32` alias) and then `add_route` for
   `fd5a:5052::/32`. The node run showed the alias alone already installs
   the on-link `/32` route, making the explicit `add_route` an idempotent
   no-op (its "File exists" path verifies the existing route is via this
   utun, zipline#100). Evidence: `netstat -rn -f inet6` before and after
   activation — the `fd5a:5052::/32 … utun9` route exists, attributed
   on-link; no error or `replacing` line in the adapter log.
   `[ ] PASS / [ ] FAIL: ______________________________________________`
2. **`tun_if` set and unset both start.** Run once with `tun_if = "utun9"`
   (the main run above) and once with the `tun_if` line removed
   (kernel-chosen `utunN`, zipline#161's `new_mq` path). Evidence: both
   starts reach ACTIVE; `ifconfig` shows the created interface; with the
   key unset, note the name the kernel chose.
   `[ ] PASS / [ ] FAIL: ______________________________________________`
3. **Bidirectional traffic through the Mac adapter.** The ping + HTTP
   fetch Mac→Linux and the ping Linux→Mac from section 3. Evidence: 0%
   loss on the 4-packet pings, the directory listing, the blob fetch
   completing.
   `[ ] PASS / [ ] FAIL: ______________________________________________`
4. **Application firewall.** With the firewall enabled, does the
   outbound-originated dock work untouched, and does the inbound reverse
   ping (Linux→Mac through the utun) arrive? Evidence: the
   add-nothing-first procedure from "Prerequisites, Mac"; record the final
   required `socketfilterfw` command set (possibly none — the firewall may
   be off, or may not inspect utun traffic at all; record which).
   `[ ] dock affected?  [ ] inbound ping affected?  Fix: ________________`
5. **Throughput through the single `posix_unbatched` worker** (macOS
   forces one worker — `new_mq` rejects more). Evidence: the flood-ping
   loss % and the `blob` download rate from section 3, recorded verbatim.
   Numbers only — no tuning in this task.
   `loss: ________ %   rate: ________ bytes/s`
6. **Shutdown.** Ctrl-C in the adapter terminal: graceful-shutdown log
   lines (`Got SIGINT; attempting graceful shutdown`), the process exits
   on its own, and the utun is gone (`ifconfig utun9` reports no such
   interface — a utun is process-scoped, so its address and route must die
   with the process; confirm `netstat -rn -f inet6` carries no stale
   `fd5a:5052` route). The node logs the dock link going down (`node.log`
   on the Linux side). Then start `ph adapter` a second time with the same
   command line: it must come up without failing on a stale route, a stale
   `utun9`, or the zipline#101 route-owner check tripping on leftovers
   from the first run.
   `[ ] PASS / [ ] FAIL: ______________________________________________`

## 5. Teardown

Mac: Ctrl-C already stopped the adapter (section 4, item 6); if a
`socketfilterfw` rule was added in item 4 and you want it gone:

```sh
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --remove ~/zpr-adapter/ph
```

Linux: identical to `windows-adapter-test.md` section 5 — `kill` the
background jobs in the container, delete the namespaces and `tun-n`, exit,
`rm -rf "$WORK"`.

## Recording the result

Paste the transcript (adapter startup lines, `ph-cli` output from both
sides, `netstat`/`ifconfig` route evidence, ping/HTTP/rate output, shutdown
and the post-exit `ifconfig`) on the PR or issue the run verifies, and fill
in **Findings** below in the same PR.

Packet captures, if needed: `tcpdump -ni utun9` works on the Mac;
`ip netns exec zpr-a tcpdump -ni tun0` on the Linux side.

## Findings

*(filled in by the first run; keep one dated subsection per run)*

### 2026-10-05 — first run (zipline#174)

* Build commit (`zl-zpr-core`): `c3ef5ba` (Mac and Linux host) · vs
  `0fafaea` (`zl-zpr-visaservice`)
* macOS version / chip: macOS 26.5.2 (25F84) / Apple M2
* Substrate: Mac and Linux host on the same home LAN (Linux host on
  Wi-Fi), `HOST_LAN_IP=192.168.0.212`.
* Three adapter runs: run 1 `tun_if = "utun9"` (all checks), run 2 the same
  command line again (item 6 second start), run 3 `tun_if` removed (item 2).

| # | Checklist item | Result | Evidence / issue |
|---|---|---|---|
| 1 | dock-time addressing + route shape | PASS | Before: no `fd5a:5052` route, no `utun9`. After ACTIVE: `utun9` carries `inet6 fd5a:5052:8888::4:1 prefixlen 32`; `netstat` shows `fd5a:5052::/32 fe80::…%utun9 Uc utun9` (on-link, no `S` flag — the alias installed it, `add_route` was the idempotent no-op) and `fd5a:5052:8888::4:1 link#21 UHL lo0`. No error, `File exists` or `replacing` line in the log; the only WARN is packet steering. |
| 2 | `tun_if` set (`utun9`) and unset (kernel-chosen) both start | PASS | Both reach `becoming ACTIVE`. Unset: the kernel chose `utun6` (system had `utun0`–`utun5`); route on `utun6`, ping both ways and HTTP OK. Minor: the adapter log never names the utun it created — the name came from `ifconfig -l`. |
| 3 | bidirectional traffic (ping + HTTP both ways) | PASS | Mac→`adapter1` `ping6 -c 4`: 0.0% loss; HTTP `/` returns the `http.server` listing; 64 MiB `blob` fetch completes. `zpr-a`→Mac `ping -6 -c 4`: 0% loss. |
| 4 | application firewall: dock / inbound ping, `socketfilterfw` fix | N-A | Firewall disabled (`socketfilterfw --getglobalstate`: State = 0) and left off for this run; neither dock nor inbound ping exercised against it. Fix: none needed with the firewall off. |
| 5 | single-worker throughput (numbers) | recorded | `ping6 -c 500 -i 0.02`: 0.0% loss, rtt 6.654/9.565/16.217 ms. `blob`: 67108864 bytes at 3854327 bytes/s (~31 Mbit/s), over the Wi-Fi substrate. |
| 6 | Ctrl-C teardown + clean second start | PASS | `Got SIGINT; attempting graceful shutdown`, `Received terminate response for dock link`, process exits on its own; `ifconfig utun9`: does not exist; no `fd5a:5052` route left. Node: `Received terminate for link 5 with reason Shutdown` … `Removed peer link 5`. Run 2 with the same command line: control socket rebinds, ACTIVE, route back on `utun9`, ping 0% loss — no stale-route or zipline#101 owner-check trip. `/var/run/zpr/501/control.sock` is left on disk after exit but does not block the rebind. |
