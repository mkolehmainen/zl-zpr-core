# Setting up a ZPRnet by hand

A step-by-step walkthrough of standing up a minimal ZPRnet: one node, one
visa service, and the adapters that connect them. It ends with a reference
for the control socket and for certificate verification.

The scripts in [`../integration-test/`](../integration-test/) do all of this
automatically on network namespaces; read them when a step here is unclear
or has drifted.

You need these binaries on hand:

* `ph` from this repository (`make`, then `target/debug/ph`).
* `vs` from the [zpr-visaservice repository](https://github.com/org-zpr/zpr-visaservice).
* `zplc` from the [zpr-compiler repository](https://github.com/org-zpr/zpr-compiler),
  unless you already have a compiled policy.

A minimal ZPRnet has a node and a visa service. You will probably also
want a service or two that run on the net, plus some client adapters
that connect in and access the services.


## Create authentication keys to share with the visa service

In order to connect to the initial ZPRnet each adapter needs to share an
RSA key with the visa service.  This is done via policy.  Since we are
going to need a node and a visa service we need two keys.

```sh
openssl genrsa -out node-private-key.pem
openssl genrsa -out vs-private-key.pem
```

The private keys stay with the visa service adapter and node, but we need
to put the public keys in the policy, so first extract them:

```sh
openssl rsa -in node-private-key.pem -pubout -out node-public-key.pem
openssl rsa -in vs-private-key.pem -pubout -out vs-public-key.pem
```

Then in the policy `zplc` file, add a bootstrap section that looks like
this:

```toml
[bootstrap]
"node.zpr.org" = "/path/to/node-public-key.pem"
"vs.zpr" = "/path/to/vs-public-key.pem"
```


## Create a certificate authority keypair

In addition to the visa service authentication, there is a separate
authentication check when the link is first brought up between an adapter
and a node.  This uses certificates holding noise keys and signed by a
certificate authority (CA).  Adapters verify the certs they get from
a node.  So we need a certificate authority:

We'll put the authority related file into a directory named `authority`.
You will be prompted for a pass phrase. You'll need to use that whenever
you sign a certificate using the authority key.

```bash
# A place to put the files
mkdir authority

cd authority

# New key for the CA
openssl genrsa -aes256 -out auth-ca.key 4096

# New self-signed cert
openssl req -x509 -new -nodes -key auth-ca.key -sha256 -days 1826 -out auth-ca.crt
```

## Create a signed noise certificate for the node

Using the handy `zpr-pki` script:

```sh
./integration-test/lib/zpr-pki genkey >node-noise.key

# First extract a public key from the private one
./integration-test/lib/zpr-pki pubkey <node-noise.key >node-noise-pub.pem

# Then sign the public key
./integration-test/lib/zpr-pki gensignedcert authority/auth-ca.crt authority/auth-ca.key \
  /CN=node.zpr.org 365 < node-noise-pub.pem >node-noise.crt
```

## Create TLS credentials for the visa service

These are used over the HTTPS admin interface.  By default the visa service will
look for two files:

- `admin-tls-cert.pem`
- `admin-tls-key.pem`

Create them like so:

```sh
openssl req -new -newkey rsa:4096 -x509 -sha256 -days 365 -nodes -out admin-tls-cert.pem -keyout admin-tls-key.pem
```


## Create a configuration file for your node

Assuming:
- Node substrate (dock) address is `129.6.7.1`
- Node ZPR address is `fd5a:5052:90de::1`

Sample configuration, place in a file named `node-conf.toml`.

```toml
[global]
# ca_file is needed for the node to verify adapter certificates and recognize
# the visa-service adapter as special.  Without it, VS routing will not work.
ca_file = "authority/auth-ca.crt"
certificate_file = "node-noise.crt"
private_key_file = "node-noise.key"
self_addr = "129.6.7.1:5000"
zpr_addr = [ "fd5a:5052:90de::1" ]
tun_if = "tun9"

[authentication]
auth_private_key = "node-private-key.pem"
```


## Create a signed noise certificate for the visa service adapter

The visa service adapter must present a CA-signed certificate so the node can
recognize it as the special visa-service peer.  The certificate CN **must** be
`vs.zpr` — that is the hard-coded visa-service distinguished name the node
matches against.  Generate and sign one:

```sh
./integration-test/lib/zpr-pki genkey >vs-noise.key
./integration-test/lib/zpr-pki pubkey <vs-noise.key >vs-noise-pub.pem
./integration-test/lib/zpr-pki gensignedcert authority/auth-ca.crt authority/auth-ca.key \
  /CN=vs.zpr 365 < vs-noise-pub.pem >vs-noise.crt
```


## Create a configuration file for the visa service adapter

Sample configuration, place in a file named `adapter-vs-conf.toml`.

```toml
[global]
# ca_file is optional for link establishment, but the VS adapter must present
# a CA-signed certificate_file so the node can recognize it as the visa service.
ca_file = "authority/auth-ca.crt"
certificate_file = "vs-noise.crt"   # CN must be "vs.zpr"
private_key_file = "vs-noise.key"
zpr_addr = [ "fd5a:5052::1" ]
tun_if = "tun9"

[adapter]
node_addr = "129.6.7.1:5000"
node_public_key_file = "node-noise-pub.pem"
bootstrap_key = "vs-private-key.pem"
```

`name` is not set here because `certificate_file` is present — the CN is read
from the certificate, not from `name`.  `name` is only required for adapters
that have no `certificate_file` (self-signed cert path).


## Configure the visa service (optional)

The visa service does not require custom configuration. However if you want
to customize it you can get it to spit out a configuration file. The default
name for it is `vs.toml`, so:

```sh
./vs --gen-config >vs.toml
```


## Start Valkey

Valkey is **required** by the visa service.

On linux systems it may be installed as a service:

```sh
# check status
systemctl status valkey-server

# and if not running:
systemctl start valkey-server
```

Or you can just start it in the foreground in a terminal:

```sh
valkey-server
```


## Write a policy and compile it.

Here is a simple policy to let any connected "user" access a "WebService".

We assume:
- WebService is connected using an adapter with `CN=web.zpr.org`.
- WebService has a bootstrap public RSA key in `web-public-key.pem`.
- WebService is accessed using HTTP port 80.

Create a file called `zpr-full-access.zpl` with these contents:

```
Define WebService as a service with device.zpr.adapter.cn:'web.zpr.org'.
Allow user to access WebService.
```

Then write a configuration file.
Create a file called `zpr-full-access.zplc` with these contents.

```toml
[nodes."node"]
provider = [ ["device.zpr.adapter.cn", "node.zpr.org"]]
zpr_address = "fd5a:5052:90de::1"

[trusted_services.default]

[visa_service]
dock_node = "node"
admin_attrs = [ [ "device.zpr.adapter.cn", "admin.zpr.org" ] ]

[bootstrap]
"node.zpr.org" = "node-public-key.pem"
"web.zpr.org" = "web-public-key.pem"

[protocols.http]
l4protocol = "iana.TCP"
port = 80

[services.WebService]
protocol = "http"
```

To compile, use the compiler:

```bash
zplc zpr-full-access.zpl

# This will create the binary policy file, "zpr-full-access.bin2"
```

## Start up the node, the visa service and the visa service adapter.

Assuming you have three separate hosts for this. The node should be run
on a Linux host but other platforms may work.  This assumes Linux.  Note
that for any node or adapter where the ZPR address is specified in the
config file, and you are running on Linux, you must manually configure
the network TUN interface to work around a known bug in the Linux
TUN library we are using.

So to prepare the Linux host to run the node, first set up the tun.
In the config file above we set the name to `tun9` so we set that up
here:

```bash
# IP configuration for the node.
sudo ip tuntap add name tun9 mode tun multi_queue
sudo ip link set tun9 mtu 1400
sudo ip addr add fd5a:5052:90de::1/32 dev tun9
sudo ip link set tun9 up
```

The binary also expects to be able to access directory `/var/run/zpr`, so:

    sudo mkdir /var/run/zpr

Then you can start the node:

    sudo ./ph node -c /path/to/node-conf.toml

If the visa service is also running on linux as this guide assumes, then we
need to configure its TUN interface similar to what we did for the node.

```bash
# IP configuration for the visa service adapter.
sudo ip tuntap add name tun9 mode tun multi_queue
sudo ip link set tun9 mtu 1400
sudo ip addr add fd5a:5052::1/32 dev tun9
sudo ip link set tun9 up
```

Now start the visa service:

    ./vs /path/to/zpr-full-access.bin2

On the visa service host, in another terminal start the adapter:

    sudo ./ph adapter -c /path/to/adapter-vs-conf.toml


Now you can attach additional adapters and start up the "WebService".


## Control socket ownership and `ph-cli` access

`ph` needs root (it creates a TUN interface), but `ph-cli` should not.
`ph` decides who owns its control and capture sockets at startup, and the
socket path and permissions follow from that. There are two modes:

**Sudo/pkexec-invoked (owner known).** When `ph` is started with
`sudo ph ...` (or via `pkexec`), it recovers the invoking user from
`SUDO_UID`/`SUDO_GID` (or `PKEXEC_UID`) and puts the sockets in a per-user
directory, chowned to that user with mode `0600`:

    /var/run/zpr/<uid>/control.sock
    /var/run/zpr/<uid>/capture.sock

The per-user base is fixed at `/var/run/zpr` — deliberately not derived
from `HOME`/`XDG_DATA_HOME`, since `ph` runs in root's environment and
`ph-cli` in the user's, and the two must agree on the path.

`ph-cli`, run as that same user with no `sudo` and no `-p`, looks in the
per-user directory for its own uid first and connects directly. Because each
invoking user gets their own directory, two adapters started by two different
users on one host do not collide.

**systemd-started (owner unknown).** When `ph` is started by systemd, `su -`,
or a direct root login, there is no invoking user to recover. The sockets
stay at the shared path (`/var/run/zpr/control.sock`), and if a group
named `zpr` exists they are chgrp'd to it with mode `0660`, so members of the
`zpr` group can use `ph-cli` without sudo. If no `zpr` group exists, the
sockets are left exactly as before (root-only) and `ph` logs one warning —
creating the group is a packaging/admin choice, never a hard runtime
dependency.

`ph-cli`'s default search order is: the per-user socket for your uid, then
the shared socket. A candidate is chosen by actually connecting to it, not
by checking the pathname exists — a stale socket file left behind by a dead
`ph` (nothing unlinks it on a crash) never shadows a live server at the
other path. If neither answers, `ph-cli` fails with an error naming both
paths tried. An explicit `-p` (control) or `-c`
(capture) always wins, on both `ph` and `ph-cli`, as does an explicit
`control_path`/`capture_path` in the config file — so multi-adapter and test
setups keep full control.

**Security note.** Reaching the control socket means being able to start and
stop links and register an `AuthAgent` — i.e. to supply and observe user
credentials for this adapter, and to receive the IdP `client_secret` in a
HelloResponse. Socket access is adapter control. Membership in the `zpr`
group grants exactly that, so treat it accordingly: it is not a low-privilege
convenience group.


## Certificate and peer verification reference

### Local certificate (`certificate_file` / `name`)

| Role | `certificate_file` | `name` | Behavior |
|------|-------------------|--------|-----------|
| node | required | ignored | Provided cert is used; node name comes from the cert CN |
| adapter | present | optional | Provided cert is used; CN comes from the cert where needed |
| adapter | absent | required | Self-signed cert is generated with CN from `name` |
| adapter | absent | absent | Config validation fails |

For adapters, CLI `--name` overrides `[adapter].name` in the config file.

### Peer certificate verification (`ca_file`)

| `ca_file` | Behavior |
|-----------|-----------|
| present | Peer cert signatures are verified against the CA; unverified peers are handled by link-type rules (see below) |
| absent | Peer cert signatures are not CA-verified; a warning is logged at startup and unverified peers are accepted |

Link-type rules when `ca_file` is configured:

| Link direction | Unverified peer cert | Action |
|---------------|---------------------|--------|
| Adapter → Node | Node cert unverified | Link rejected |
| Node → Node | Peer node cert unverified | Link rejected |
| Node → Adapter | Adapter cert unverified | Link accepted with a warning |

### Special peers (visa service adapter)

The visa service adapter is recognized as "special" by the node **only** when
the adapter presents a CA-verified certificate claiming the visa-service DN.
This means:

- The **node** must configure `ca_file` (to verify the VS adapter's cert).
- The **VS adapter** must present a CA-signed `certificate_file` (not a self-signed cert).

Without both conditions, the VS adapter connects as an ordinary adapter and
visa-service traffic is not routed to it.
