# Rahro — multi-stage build producing the panel, node, server and client.
FROM golang:1.26-alpine AS build
WORKDIR /src
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=0.0.0-dev
ENV CGO_ENABLED=0
RUN set -e; \
    LD="-s -w -X github.com/awmiresgg/rahro/core/version.Version=${VERSION}"; \
    for c in rahro-panel rahro-node rahro-server rahro-client; do \
      go build -trimpath -ldflags "$LD" -o /out/$c ./cmd/$c; \
    done

FROM alpine:3.20
RUN apk add --no-cache ca-certificates curl && mkdir -p /data
COPY --from=build /out/ /usr/local/bin/
WORKDIR /data
EXPOSE 443 2053
# Default: run the panel. Override the command for a node/server.
ENTRYPOINT ["rahro-panel"]
CMD ["run", "-config", "/data/panel.json"]
