# Runtime image for zl-zpr-core/integration-test.
#
# The test scripts stand up a ZPRnet on network namespaces and call `sudo`
# for every `ip netns` / `tuntap` operation, so on a developer host they need
# passwordless sudo.  Inside this container the caller is already root, so no
# host privilege is needed beyond running Docker.  See integration-test/Makefile.
#
# Nothing is built here.  The binaries (ph, ph-cli, vs, vs-admin, ...) are
# built on the host and bind-mounted in, so the base image must carry a glibc
# at least as new as the one they were linked against.  The dev-env image
# (Debian 12, glibc 2.36) is too old for that; Ubuntu 26.04 matches a current
# host.  Override with `make docker-image BASE_IMAGE=ubuntu:24.04` if needed.
ARG BASE_IMAGE=ubuntu:26.04
FROM ${BASE_IMAGE}

# sudo             the scripts call it; as root it needs no password
# iproute2         ip netns / ip link / tc
# iputils-ping     ping_test
# psmisc, procps   pstree (get_descendants), pkill / pgrep
# jq curl openssl  OIDC and attribute-service assertions
# tcpdump          capture-test.sh
# python3          lib/fake-idp.py
# valkey-server    backing store for the visa service
# libssl3t64 libzstd1 zlib1g   linked by vs, vs-admin, zpdump
# libpcap0.8t64    linked by ph-cli
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      sudo iproute2 iputils-ping psmisc procps jq curl openssl tcpdump python3 \
      valkey-server libssl3t64 libzstd1 zlib1g libpcap0.8t64 ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# The scripts derive ZPR_USER from $USER under `set -u`; Docker does not set it.
# valkey-server is not next to the scripts, so point the scripts at the package.
ENV USER=root \
    VALKEY_SERVER_BIN=/usr/bin/valkey-server \
    ZPR_TEST_VERBOSE=1
