.PHONY: test test-race test-coverage lint build clean help

# Default target
all: test lint build

# Run tests
test:
	go test -v ./...

# Run tests with race detection
test-race:
	go test -v -race ./...

# Run tests with coverage
test-coverage:
	go test -v -cover ./...

# Generate detailed coverage report
coverage:
	go test -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Run linters
lint:
	@echo "Running gofmt..."
	@if [ "$$(gofmt -s -l . | wc -l)" -gt 0 ]; then \
		echo "The following files are not formatted:"; \
		gofmt -s -l .; \
		exit 1; \
	fi
	@echo "Running go vet..."
	go vet ./...
	@echo "Running staticcheck..."
	@if command -v staticcheck >/dev/null 2>&1; then \
		staticcheck ./... || echo "Staticcheck found issues, but continuing..."; \
	else \
		echo "staticcheck not installed, skipping..."; \
	fi

# Build the project
build:
	go build -v ./...

# Build example
build-example:
	@if [ -d "./cmd" ]; then \
		go build -v -o example ./cmd/...; \
	else \
		echo "No cmd directory found, skipping example build"; \
	fi

# Clean build artifacts
clean:
	go clean
	rm -f coverage.out coverage.html example

# Install dependencies
deps:
	go mod download
	go mod verify

# Update dependencies
update-deps:
	go get -u ./...
	go mod tidy

# Show help
help:
	@echo "Available targets:"
	@echo "  test          - Run tests"
	@echo "  test-race     - Run tests with race detection"
	@echo "  test-coverage - Run tests with coverage"
	@echo "  coverage      - Generate detailed coverage report"
	@echo "  lint          - Run linters (gofmt, go vet, staticcheck)"
	@echo "  build         - Build the project"
	@echo "  build-example - Build the example"
	@echo "  clean         - Clean build artifacts"
	@echo "  deps          - Download and verify dependencies"
	@echo "  update-deps   - Update dependencies"
	@echo "  help          - Show this help message"
