

info:
	@echo 
	@echo Welcome to ZPR core
	@echo ===================
	@echo 
	@echo Build your own adventure:
	@echo "  make           - build everything!"
	@echo "  make test      - run all unit tests!"
	@echo "  make clean     - clean everything!"
	@echo "  make diagrams  - build PlantUML diagrams"
	@echo "  make integration-test-docker - run integration-test/ in Docker (no host sudo needed)"
	@echo 
	@echo The resulting binaries are found in \`./target/debug\`.
	@echo
	@echo \>_
	@echo

help: info

all: 
	cargo build && cargo build -p libnode2 --all-features

test:
	cargo test

clean:
	cargo clean
	rm -rf diagrams/output


diagrams:
	$(MAKE) -C diagrams


zpr-crate-related:
	$(MAKE) -C libnode2
	$(MAKE) -C adapter/ph


# The integration tests need root for network namespaces; this runs them as
# root inside a Docker container instead.  See integration-test/Makefile.
integration-test-docker:
	$(MAKE) -C integration-test docker-test


.PHONY: info help all test clean diagrams zpr-crate-related integration-test-docker

.DEFAULT_GOAL := all
