# Rahro — build & test targets.
# Pure-Go, CGO disabled, so binaries cross-compile cleanly to Linux & Windows.

MODULE   := github.com/awmiresgg/rahro
VERSION  ?= $(shell git describe --tags --always 2>/dev/null || echo 0.0.0-dev)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE     := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS  := -s -w \
	-X $(MODULE)/core/version.Version=$(VERSION) \
	-X $(MODULE)/core/version.Commit=$(COMMIT) \
	-X $(MODULE)/core/version.Date=$(DATE)

export CGO_ENABLED := 0

.PHONY: all build test vet fmt tidy clean build-linux build-windows

all: fmt vet test build

build:
	go build -ldflags "$(LDFLAGS)" ./...

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

tidy:
	go mod tidy

# Cross-compiled server binaries for the two supported server OSes.
build-linux:
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/rahro-server-linux-amd64 ./cmd/rahro-server

build-windows:
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/rahro-server-windows-amd64.exe ./cmd/rahro-server

clean:
	rm -rf dist
