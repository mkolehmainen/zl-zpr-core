#!/usr/bin/env bash


# Our PKI helper tool
ZPR_PKI_BIN=$(realpath "$(dirname $0)/lib/zpr-pki")


#
# Functions used in multiple integration tests
#

function prefix_log() {
  SYSNAME=$1
  printf -v PREFIX '%10s' "[$SYSNAME]"
  sed "s/^/$PREFIX /"
}

function wait_for() {
  RETRIES=$1
  shift
  CMD=("$@")

  if "${CMD[@]}"
  then return 0
  else RET=$?
  fi

  for ((i = 0; i < RETRIES; ++i))
  do
    sleep 1

    if "${CMD[@]}"
    then return 0
    else RET=$?
    fi
  done

  return "$RET"
}

# Print the PID of the ph process serving control socket $1, or nothing if
# there is none. Expects PH_BIN to be the ph binary path.
#
# The tests launch ph through a chain of wrappers
# (`sudo ... ip netns exec ... sudo ... env ... $PH_BIN ... --control-path S`),
# and every wrapper's command line contains "--control-path S" too. A bare
# match on the socket finds the outermost sudo first, and a signal sent to it
# is not reliably passed on to ph (under sudo-rs it is not passed on at all),
# so the pattern is anchored on $PH_BIN: env execs ph, so only ph's own
# command line starts with it (zipline#116).
function ph_pid_for_socket() {
  pgrep -f "^$PH_BIN .*--control-path $1( |\$)" | head -n 1 || true
}

# Succeed once process $1 no longer exists. Uses ps rather than `kill -0`,
# which fails with EPERM on a live process owned by another user (ph runs
# as $ZPR_USER) and would read as "exited".
function process_exited() {
  ! ps -p "$1" > /dev/null
}

function create_network() {
  sudo ip netns add zpr-node
  sudo ip netns add zpr-vs
  sudo ip netns add zpr-a
  sudo ip netns add zpr-b
  sudo ip netns add zpr-c

  # loopback

  sudo ip -n zpr-node link set lo up
  sudo ip -n zpr-vs link set lo up
  sudo ip -n zpr-a link set lo up
  sudo ip -n zpr-b link set lo up
  sudo ip -n zpr-c link set lo up

  # virtual Ethernet pair

  # Kernel bug: Linux refuses to create a veth device in a netns with
  # a name matching that of a veth device in the root ns, but not the other
  # way around.  And weirdly, it will happily _autogenerate_ such names.
  # So we rely on that for now rather than explicitly specifying the names.
  sudo ip link add netns zpr-vs type veth peer veth-zpr-vs netns zpr-node  # zpr-a:veth0 / zpr-node:veth-zpr-vs
  sudo ip link add netns zpr-a type veth peer veth-zpr-a netns zpr-node  # zpr-a:veth0 / zpr-node:veth-zpr-a
  sudo ip link add netns zpr-b type veth peer veth-zpr-b netns zpr-node  # zpr-b:veth0 / zpr-node:veth-zpr-b
  sudo ip link add netns zpr-c type veth peer veth-zpr-c netns zpr-node  # zpr-c:veth0 / zpr-node:veth-zpr-c

  # Each substrate link gets a /24 rather than a point-to-point
  # "addr add ADDR peer PEER" pair.  Peer addressing is tempting here -- every
  # link really does have exactly two endpoints -- but the local address it
  # produces is a /32, and the kernel does not answer ARP requests for such an
  # address on an ARP-capable device like veth.  The neighbour entry then stays
  # INCOMPLETE forever, so no substrate packet ever reaches the far end, and
  # every adapter fails to dock.  (tun0 below is a different case: a TUN device
  # is NOARP, so peer addressing works there and is used.)
  sudo ip -n zpr-node addr add "$NODE_SUBSTRATE_ADDR_VS/24" dev veth-zpr-vs
  sudo ip -n zpr-node addr add "$NODE_SUBSTRATE_ADDR_A/24" dev veth-zpr-a
  sudo ip -n zpr-node addr add "$NODE_SUBSTRATE_ADDR_B/24" dev veth-zpr-b
  sudo ip -n zpr-node addr add "$NODE_SUBSTRATE_ADDR_C/24" dev veth-zpr-c
  if [ -n "${NODE_SUBSTRATE_ADDR_C_ALT-}" ]
  then sudo ip -n zpr-node addr add "$NODE_SUBSTRATE_ADDR_C_ALT/24" dev veth-zpr-c  # Used for testing routing.
  fi
  sudo ip -n zpr-vs addr add "$VS_SUBSTRATE_ADDR/24" dev veth0
  sudo ip -n zpr-a addr add "$A_SUBSTRATE_ADDR/24" dev veth0
  sudo ip -n zpr-b addr add "$B_SUBSTRATE_ADDR/24" dev veth0
  sudo ip -n zpr-c addr add "$C_SUBSTRATE_ADDR/24" dev veth0

  sudo ip -n zpr-node link set veth-zpr-vs up
  sudo ip -n zpr-node link set veth-zpr-a up
  sudo ip -n zpr-node link set veth-zpr-b up
  sudo ip -n zpr-node link set veth-zpr-c up
  sudo ip -n zpr-vs link set veth0 up
  sudo ip -n zpr-a link set veth0 up
  sudo ip -n zpr-b link set veth0 up
  sudo ip -n zpr-c link set veth0 up

  # TUN devices

  sudo ip -n zpr-node tuntap add name tun0 mode tun user "$ZPR_USER" multi_queue
  sudo ip -n zpr-vs tuntap add name tun0 mode tun user "$ZPR_USER" multi_queue
  sudo ip -n zpr-a tuntap add name tun0 mode tun user "$ZPR_USER" multi_queue
  sudo ip -n zpr-b tuntap add name tun0 mode tun user "$ZPR_USER" multi_queue
  sudo ip -n zpr-c tuntap add name tun0 mode tun user "$ZPR_USER" multi_queue

  sudo ip -n zpr-node link set tun0 up
  sudo ip -n zpr-vs link set tun0 up
  sudo ip -n zpr-a link set tun0 up
  sudo ip -n zpr-b link set tun0 up
  sudo ip -n zpr-c link set tun0 up

  # Kernel bug: kernels older than 6.10 don't set peer route correctly
  # when interface is down.  I think <https://github.com/torvalds/linux/commit/d0098e4c6b83e502cc1cd96d67ca86bc79a6c559>
  # fixes this issue.  For now, add the addresses after we bring the link up.
  sudo ip -n zpr-node addr add "$NODE_ZPR_ADDR" peer "$VS_ZPR_ADDR" dev tun0
  sudo ip -n zpr-vs addr add "$VS_ZPR_ADDR" peer "$NODE_ZPR_ADDR" dev tun0
  sudo ip -n zpr-a addr add "$A_ZPR_ADDR" peer "$ZPR_SUBNET" dev tun0
  sudo ip -n zpr-b addr add "$B_ZPR_ADDR" peer "$ZPR_SUBNET" dev tun0
  sudo ip -n zpr-c addr add "$C_ZPR_ADDR" peer "$ZPR_SUBNET" dev tun0
}

function configure_netem() {
  echo "Configuring netem $@" > /dev/stderr
  for NIC in vs a b c
  do
    sudo tc -n zpr-node qdisc add dev veth-zpr-"$NIC" root netem "$@"
  done
}

function destroy_network() {
  sudo ip netns delete zpr-node 2> /dev/null || true
  sudo ip netns delete zpr-vs 2> /dev/null || true
  sudo ip netns delete zpr-a 2> /dev/null || true
  sudo ip netns delete zpr-b 2> /dev/null || true
  sudo ip netns delete zpr-c 2> /dev/null || true
}

function create_ca_key_and_cert() {
  CA_NAME=$1
  # We can't do this properly until we pull in the policy compiler
  # So just use the pair set up in the examples directory for now
  cp "$PREGEN/ca-key.pem" "$CA_NAME.key"
  cp "$PREGEN/ca-cert.pem" "$CA_NAME.crt"
  #"$ZPR_PKI_BIN" gencakey >"$CA_NAME.key"
  #"$ZPR_PKI_BIN" gencacert /CN="$CA_NAME" 1 <"$CA_NAME.key" >"$CA_NAME.crt"
  #openssl genrsa -out "$CA_NAME.key"
  #openssl x509 -new -subj /CN="$CA_NAME" -key "$CA_NAME.key" -extfile /etc/ssl/openssl.cnf -extensions v3_ca -days 1 -out "$CA_NAME.crt"
}

function create_actor_key_and_cert() {
  CA_NAME=$1
  ACTOR_NAME=$2
  "$ZPR_PKI_BIN" genkey >"$ACTOR_NAME.key"
  "$ZPR_PKI_BIN" pubkey <"$ACTOR_NAME.key" >"$ACTOR_NAME.pubkey"
  "$ZPR_PKI_BIN" gensignedcert "$CA_NAME.crt" "$CA_NAME.key" /CN="$ACTOR_NAME" 1 <"$ACTOR_NAME.pubkey" >"$ACTOR_NAME.crt"
  
  #openssl genrsa -out "$ACTOR_NAME.key"
  #openssl req -new -subj /CN="$ACTOR_NAME" -key "$ACTOR_NAME.key" -config /etc/ssl/openssl.cnf -reqexts v3_req -out "$ACTOR_NAME.csr" 2> /dev/null
  #openssl x509 -req -CA "$CA_NAME.crt" -CAkey "$CA_NAME.key" -copy_extensions copyall -days 1 -in "$ACTOR_NAME.csr" -out "$ACTOR_NAME.crt" 2> /dev/null
}

function emit_vs_config() {
  # Args retained for backward compatibility with existing callers.
  CA_NAME=$1
  VS_ACTOR_NAME=$2
  cat <<EOF
[core]
admin_cert = "$(realpath "$PREGEN/zpr-rsa-cert.pem")"
admin_key = "$(realpath "$PREGEN/zpr-rsa-key.pem")"
vk_uri = "redis://127.0.0.1:6379"
EOF
}

# Install the shared static-address store for the `addresses` file trusted
# service (zipline#107). Every fixture policy that declares
# [trusted_services.addresses] gets its data from pregen/addresses.json: one
# CN-keyed store granting adapter1/2/3 their static ZPR addresses via
# device.zpr_addr (zipline#99), plus a user-keyed entry for the user-only
# OIDC adapter1 (its CN is never authenticated, so the grant is keyed on the
# user identity the policy maps `sub` to). The visa service reads
# <file_ts_dir>/addresses.json, and file_ts_dir defaults to the directory of
# the vs config file — call this from that directory (the test's $TMPDIR),
# like the happyfile/attr-query copies.
function copy_address_store() {
  cp "$PREGEN/addresses.json" addresses.json
}

function check_vs_valkey_port() {
  sudo ip netns exec zpr-vs bash -lc 'exec 3<>/dev/tcp/127.0.0.1/6379'
}

function ping_test() {
  RESULT=0

  sudo ip netns exec zpr-node ping -q -c 5 -w 5 "$VS_ZPR_ADDR" & wait -f $!; let RESULT="RESULT||$?"
  sudo ip netns exec zpr-vs ping -q -c 5 -w 5 "$NODE_ZPR_ADDR" & wait -f $!; let RESULT="RESULT||$?"
  sudo ip netns exec zpr-a ping -q -c 5 -w 5 "$B_ZPR_ADDR" & wait -f $!; let RESULT="RESULT||$?"
  sudo ip netns exec zpr-b ping -q -c 5 -w 5 "$A_ZPR_ADDR" & wait -f $!; let RESULT="RESULT||$?"

  if [[ "$NUM_ACTORS" -ge 3 ]]; then
    sudo ip netns exec zpr-a ping -q -c 5 -w 5 "$C_ZPR_ADDR" & wait -f $!; let RESULT="RESULT||$?"
    sudo ip netns exec zpr-b ping -q -c 5 -w 5 "$C_ZPR_ADDR" & wait -f $!; let RESULT="RESULT||$?"
    sudo ip netns exec zpr-c ping -q -c 5 -w 5 "$A_ZPR_ADDR" & wait -f $!; let RESULT="RESULT||$?"
    sudo ip netns exec zpr-c ping -q -c 5 -w 5 "$B_ZPR_ADDR" & wait -f $!; let RESULT="RESULT||$?"
  fi

  return "$RESULT"
}

function check_carrier() {
  NETNS=$1
  IF=$2

  return $(( ! $(sudo ip netns exec "$NETNS" cat "/sys/class/net/$IF/carrier") ))
}

# Visible sleep for n seconds.  Takes one arg: number of seconds.
function countdown() {
    count=$1
    (( ++count ))
    while (( --count > 0 )); do
        echo -n "$count...   "
        sleep 1
    done
    echo
}

# Get all descendant PIDs whose name matches a specific list
function get_descendants() {
    exenames="(ph|node|adapter|vservice|vs|valkey-server)"
    regex="$exenames\(([0-9]+)\)"
    echo $(pstree -pT "$$" | egrep -o "$regex" | sed -E "s/$regex/\2/")
}

# Takes one arg- filepath relative to TMPDIR
function emitlog() {
    echo -e "\n\n==== $1 ====\n"
    if [ -e "$TMPDIR/$1" ]
        then
            cat "$TMPDIR/$1"
        else
            echo "(MISSING)"
    fi
}


function cleanup() {
  for child in $(jobs -p)
  do kill -9 "$child" 2> /dev/null || true
  done

  wait -f

  destroy_network || true

  SHOW_LOGS="${ZPR_TEST_VERBOSE:-no}"

  if [ "$SHOW_LOGS" != "no" ]
     then
         emitlog "valkey.log"
         emitlog "node.log"
         emitlog "vs.log"
         # The VS's own adapter has to dock before the node can reach the visa
         # service at all, so its log is emitted with the rest of them.
         emitlog "adapter-vs.log"
         emitlog "adapter1.log"
         emitlog "adapter2.log"
         emitlog "adapter3.log"
  fi

  popd > /dev/null
  rm -r "$TMPDIR" || true
}
