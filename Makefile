.PHONY: all dev web test test-race lint build demo screenshots doctor clean release-check

BINARY_NAME=agentpcap

all: web build

dev:
	@echo "Starting web development server and live capture backend..."
	cd web && pnpm dev

web:
	@echo "Building web frontend..."
	cd web && pnpm install && pnpm build

build:
	@echo "Building AgentPCAP single binary..."
	go build -ldflags="-s -w" -o $(BINARY_NAME) ./cmd/agentpcap

test:
	@echo "Running unit tests..."
	go test -v ./...

test-race:
	@echo "Running race tests..."
	go test -race ./...

lint:
	@echo "Running static checks..."
	go vet ./...

demo:
	@echo "Running local multi-agent demo..."
	go run ./cmd/agentpcap demo

screenshots:
	@echo "Generating sample capture and exporting artifacts..."
	go run ./cmd/agentpcap demo --no-browser --output demo.apcap
	go run ./cmd/agentpcap report demo.apcap -o report.html
	@echo "Demo capture and standalone HTML report generated."

doctor:
	@echo "Running diagnostic health checks..."
	go run ./cmd/agentpcap doctor

clean:
	rm -f $(BINARY_NAME) $(BINARY_NAME).exe demo.apcap test_run.apcap report.html safe.apcap demo_check.apcap
	rm -rf web/dist dist

release-build: web
	@echo "Compiling release binaries..."
	mkdir -p dist
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w -X github.com/agentpcap/agentpcap/internal/version.Version=1.0.0 -X github.com/agentpcap/agentpcap/internal/version.Commit=fa02f45 -X github.com/agentpcap/agentpcap/internal/version.BuildDate=2026-09-04" -o dist/agentpcap_1.0.0_windows_amd64.exe ./cmd/agentpcap
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w -X github.com/agentpcap/agentpcap/internal/version.Version=1.0.0 -X github.com/agentpcap/agentpcap/internal/version.Commit=fa02f45 -X github.com/agentpcap/agentpcap/internal/version.BuildDate=2026-09-04" -o dist/agentpcap_1.0.0_linux_amd64 ./cmd/agentpcap
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w -X github.com/agentpcap/agentpcap/internal/version.Version=1.0.0 -X github.com/agentpcap/agentpcap/internal/version.Commit=fa02f45 -X github.com/agentpcap/agentpcap/internal/version.BuildDate=2026-09-04" -o dist/agentpcap_1.0.0_linux_arm64 ./cmd/agentpcap
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w -X github.com/agentpcap/agentpcap/internal/version.Version=1.0.0 -X github.com/agentpcap/agentpcap/internal/version.Commit=fa02f45 -X github.com/agentpcap/agentpcap/internal/version.BuildDate=2026-09-04" -o dist/agentpcap_1.0.0_darwin_arm64 ./cmd/agentpcap
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w -X github.com/agentpcap/agentpcap/internal/version.Version=1.0.0 -X github.com/agentpcap/agentpcap/internal/version.Commit=fa02f45 -X github.com/agentpcap/agentpcap/internal/version.BuildDate=2026-09-04" -o dist/agentpcap_1.0.0_darwin_amd64 ./cmd/agentpcap

release-check: web lint test test-race
	@echo "Running spec and canonical vector verification..."
	go test -v ./spec
	@echo "Running protocol torture lab..."
	go test -v ./tests/torture
	@echo "Running independent third-party reader test..."
	go test -v -run TestThirdPartyReader ./pkg/apcap
	@echo "Running demo fixture verification..."
	go run ./cmd/agentpcap demo --no-browser --output demo_check.apcap
	go run ./cmd/agentpcap validate demo_check.apcap
	go run ./cmd/agentpcap explain demo_check.apcap
	go run ./cmd/agentpcap check demo_check.apcap
	rm -f demo_check.apcap
	@echo "All release checks passed successfully! Ready for v1.0.0."
