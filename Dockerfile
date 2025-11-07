FROM golang:1.25.0-bookworm AS builder
WORKDIR /src

COPY go.mod go.sum .
RUN \
    --mount=type=cache,target=/go/pkg/mod \
    go mod download

RUN \
    --mount=type=cache,target=/go/pkg/mod \
    --mount=type=bind,target=. \
    CGO_ENABLED=0 go build -ldflags "-s -w" -mod=readonly -o=/artifact/program ./cmd/rest-api/

FROM cgr.dev/chainguard/wolfi-base:latest
WORKDIR /bin

COPY --from=builder --chown=nonroot:nonroot /artifact/program /bin
USER nonroot

ENTRYPOINT ["/bin/program"]
