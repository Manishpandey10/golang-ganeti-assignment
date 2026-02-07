.PHONY: help build run clean test

BINARY_NAME=ganetigo
GO_VERSION=1.18
GANETI_HOST?=localhost:5080

help:
	@echo "Ganeti CLI - Available commands:"
	@echo "  make build       - Build the CLI binary"
	@echo "  make run         - Run the CLI"
	@echo "  make start-ganeti - Start Ganeti Docker container"
	@echo "  make test        - Test basic connectivity to Ganeti"
	@echo "  make clean       - Remove binary"
	@echo ""
	@echo "Environment variables:"
	@echo "  GANETI_HOST      - Ganeti RAPI host (default: localhost:5080)"

build:
	@echo "Building $(BINARY_NAME)..."
	go build -o $(BINARY_NAME) main.go
	@echo "Build complete: ./$(BINARY_NAME)"

run: build
	./$(BINARY_NAME)

test: build
	@echo "Testing Ganeti connectivity to $(GANETI_HOST)..."
	./$(BINARY_NAME) -host $(GANETI_HOST) cluster info

start-ganeti:
	@echo "Starting Ganeti Docker container..."
	docker run -d -p 5080:5080 --cap-add=NET_ADMIN ghcr.io/sipgate/ganeti-docker:latest
	@echo "Container started. Waiting 15 seconds for initialization..."
	@sleep 15
	@echo "Testing connection..."
	curl -k https://localhost:5080/2/ 2>/dev/null | head -c 100
	@echo ""

clean:
	@echo "Cleaning up..."
	rm -f $(BINARY_NAME)
	go clean

stop-ganeti:
	docker stop $$(docker ps -q --filter ancestor=ghcr.io/sipgate/ganeti-docker) 2>/dev/null || true

fmt:
	go fmt ./...

vet:
	go vet ./...

lint: fmt vet

deps:
	go mod download
	go mod verify
