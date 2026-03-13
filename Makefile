.PHONY: build test check fmt clippy release proto clean check-license

SERVICES_DIR = $(PWD)/../services

build:
	cd $(SERVICES_DIR) && cargo build --workspace

build-%:
	cd $(SERVICES_DIR) && cargo build -p $*

test:
	cd $(SERVICES_DIR) && cargo test --workspace

test-%:
	cd $(SERVICES_DIR) && cargo test -p $*

check:
	cd $(SERVICES_DIR) && cargo check --workspace

fmt:
	cd $(SERVICES_DIR) && cargo fmt --all -- --check

fmt-fix:
	cd $(SERVICES_DIR) && cargo fmt --all

clippy:
	cd $(SERVICES_DIR) && cargo clippy --workspace -- -D warnings

release:
	cd $(SERVICES_DIR) && cargo build --release --workspace

proto:
	cd $(SERVICES_DIR) && cargo build -p ag-proto

clean:
	cd $(SERVICES_DIR) && cargo clean

check-license:
	@if [ -z "$$CLAMPD_LICENSE_KEY" ] && ! grep -q '^CLAMPD_LICENSE_KEY=.' .env 2>/dev/null; then \
		echo "ERROR: CLAMPD_LICENSE_KEY is not set."; \
		echo "  Generate with: ./generate-license.sh design_partner <org-id>"; \
		echo "  Then add to .env: CLAMPD_LICENSE_KEY=<your-key>"; \
		exit 1; \
	fi
	@echo "License key is set."
