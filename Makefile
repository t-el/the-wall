.PHONY: all build test lint clean docker

all: build

build: build-rust build-go

build-rust:
	cargo build --release --workspace

build-go:
	cd services/controlplane-go && go build -o ../../bin/controlplane ./...
	cd services/macert-exporter-go && go build -o ../../bin/macert-exporter ./...

test:
	cargo test --workspace
	cd services/controlplane-go && go test ./...
	cd services/macert-exporter-go && go test ./...

lint:
	cargo clippy --workspace -- -D warnings
	cd services/controlplane-go && golangci-lint run || true
	cd services/macert-exporter-go && golangci-lint run || true

docker:
	docker-compose -f deployments/docker-compose.yml up --build

clean:
	cargo clean
	rm -rf bin/
	find . -name "*.exe" -delete

# Module 2
run-crypto-demo:
	cargo test -p crypto-rust -- --nocapture

# Module 1 production
run-dataplane:
	PLAYBOOKS_DIR=scripts/playbooks-lua cargo run --release -p dataplane-rust
