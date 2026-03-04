.PHONY: dev-image build test check fmt clippy release proto clean

DOCKER_RUST = docker run --rm \
  -v $(PWD):/app \
  -v clampd-cargo-registry:/usr/local/cargo/registry \
  -v clampd-cargo-target:/app/services/target \
  -w /app/services \
  clampd-rust-dev

dev-image:
	docker build -t clampd-rust-dev -f Dockerfile.dev .

build: dev-image
	$(DOCKER_RUST) cargo build --workspace

build-%: dev-image
	$(DOCKER_RUST) cargo build -p $*

test: dev-image
	$(DOCKER_RUST) cargo test --workspace

test-%: dev-image
	$(DOCKER_RUST) cargo test -p $*

check: dev-image
	$(DOCKER_RUST) cargo check --workspace

fmt: dev-image
	$(DOCKER_RUST) cargo fmt --all -- --check

fmt-fix: dev-image
	$(DOCKER_RUST) cargo fmt --all

clippy: dev-image
	$(DOCKER_RUST) cargo clippy --workspace -- -D warnings

release: dev-image
	$(DOCKER_RUST) cargo build --release --workspace

proto: dev-image
	$(DOCKER_RUST) cargo build -p ag-proto

cli:
	docker build -f services/deploy/Dockerfile.cli -t clampd-cli .
	@mkdir -p dist
	@docker create --name clampd-extract clampd-cli 2>/dev/null || true
	@docker cp clampd-extract:/usr/local/bin/clampd ./dist/clampd
	@docker rm clampd-extract
	@chmod +x ./dist/clampd
	@echo "Binary exported to ./dist/clampd (Linux $$(uname -m))"

cli-install: cli
	sudo cp ./dist/clampd /usr/local/bin/clampd

clean:
	docker volume rm -f clampd-cargo-target
