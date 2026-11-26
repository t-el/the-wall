.PHONY: all build test lint clean docker run-dataplane

all: build

build:
	cd services/dataplane-go && go build -o ../../bin/dataplane .
	cd services/controlplane-go && go build -o ../../bin/controlplane .
	cd services/macert-exporter-go && go build -o ../../bin/macert-exporter .

test:
	cd services/dataplane-go && go test ./...
	cd services/controlplane-go && go test ./...
	cd services/macert-exporter-go && go test ./...

lint:
	cd services/dataplane-go && golangci-lint run || true
	cd services/controlplane-go && golangci-lint run || true
	cd services/macert-exporter-go && golangci-lint run || true

docker:
	docker compose -f deployments/docker-compose.yml up --build

clean:
	rm -rf bin/

run-dataplane:
	PLAYBOOKS_DIR=scripts/playbooks-lua go run ./services/dataplane-go
