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

BINS := rahro-panel rahro-node rahro-server rahro-client

.PHONY: all build test race vet fmt tidy clean dist build-linux build-windows docker

all: fmt vet test build

build:
	go build -ldflags "$(LDFLAGS)" ./...

test:
	go test ./...

race:
	CGO_ENABLED=1 go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

tidy:
	go mod tidy

# Cross-compiled release binaries for both supported server OSes.
build-linux:
	@for b in $(BINS); do \
	  GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$$b-linux-amd64 ./cmd/$$b; \
	  GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$$b-linux-arm64 ./cmd/$$b; \
	done

build-windows:
	@for b in $(BINS); do \
	  GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$$b-windows-amd64.exe ./cmd/$$b; \
	done

dist: build-linux build-windows

docker:
	docker build -t rahro:$(VERSION) .

clean:
	rm -rf dist
