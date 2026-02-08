FROM golang:1.25-alpine AS build

ARG GOARCH="amd64"
ARG GOARM=""

WORKDIR /workspace

# Install ca-certificates for SSL connections
RUN apk update && apk add --no-cache ca-certificates git

# Copy go.mod and go.sum first for better caching
COPY go.mod go.sum ./
# Mount Go module cache (persisted by buildx when using type=gha cache)
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# Copy source code
COPY . .

# Build the binary (use Go build cache to speed up repeated builds)
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOARCH=$GOARCH GOARM=$GOARM GOCACHE=/root/.cache/go-build go build -v -o webhook \
    -ldflags '-w -s -extldflags "-static"' .

# Use distroless for better security
FROM gcr.io/distroless/static:nonroot

# Copy CA certificates
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Copy the binary
COPY --from=build /workspace/webhook /webhook

# Use non-root user
USER nonroot:nonroot

ENTRYPOINT ["/webhook"]
