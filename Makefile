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

clean:
	docker volume rm -f clampd-cargo-target
