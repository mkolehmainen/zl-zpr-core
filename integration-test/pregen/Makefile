ZPLC ?= zplc
KEY := zpr-rsa-key.pem

OBJS := v4-1node-2actor-ping.bin2 v4-1node-3actor-ping.bin2 v6-1node-2actor-ping.bin2 v6-1node-3actor-ping.bin2 oidc-test.bin2

info:
	@echo Makefile to help with compiling the ZPR policies
	@echo from source.
	@echo
	@echo make clean   - removes all the .bin2 policy files
	@echo make all     - recompiles out of date policy files
	@echo make rebuild - run a clean followed by an all.
	@echo
	@echo Requires that \'zplc\' the ZPL compiler is in your path.
	@echo Or you can set path to zplc by setting ZPLC variable.
	@echo

all: $(OBJS)

clean:
	rm -f $(OBJS)

rebuild: clean all

v6-1node-2actor-ping.bin2: v6-1node-2actor-ping.zplc v4-1node-2actor-ping.zpl
	$(ZPLC) -c v6-1node-2actor-ping.zplc -k $(KEY) -f v2 -o $@ v4-1node-2actor-ping.zpl


v6-1node-3actor-ping.bin2: v6-1node-3actor-ping.zplc v4-1node-3actor-ping.zpl
	$(ZPLC) -c v6-1node-3actor-ping.zplc -k $(KEY) -f v2 -o $@ v4-1node-3actor-ping.zpl


%.bin2: %.zpl %.zplc
	$(ZPLC) -k $(KEY) $<

# OIDC integration-test fixture (zipline#16). Compiled with the same zplc
# vintage as the other fixtures; `service` is deliberately omitted from the
# trusted-service block (no CONNECT proxy in the test), so zplc emits a
# warning — expected, do not add --Werror here.
oidc-test.bin2: oidc-test.zpl oidc-test.zplc oidc-test-seed-jwks.json
	$(ZPLC) -c oidc-test.zplc -k $(KEY) -f v2 -o $@ oidc-test.zpl

# Fake-IdP signing keys (checked in; test-only, no secrecy requirement) and
# the seed JWKS derived from key 1 only via --print-jwks, which reuses the
# exact JWK construction the server's /jwks endpoint serves, so seed and
# live JWKS cannot drift. Key 2 is deliberately NOT in the seed: after
# --rotate the visa service must observe an unknown kid and refresh from
# the live /jwks, which is the stale-cache path the rotation leg tests.
fake-idp-keys: fake-idp-rsa.key fake-idp-rsa-2.key oidc-test-seed-jwks.json

fake-idp-rsa.key:
	openssl genrsa -out $@ 2048

fake-idp-rsa-2.key:
	openssl genrsa -out $@ 2048

oidc-test-seed-jwks.json: fake-idp-rsa.key
	python3 ../lib/fake-idp.py --state-dir . \
	    --signing-key fake-idp-rsa.key \
	    --print-jwks > $@


.PHONY: all clean rebuild fake-idp-keys

.DEFAULT_GOAL: info
