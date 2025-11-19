FROM golang:1.25-alpine AS build

ARG GOARCH="amd64"
ARG GOARM=""

WORKDIR /workspace

# Install ca-certificates for SSL connections
RUN apk update && apk add --no-cache ca-certificates git

# Copy go.mod and go.sum first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOARCH=$GOARCH GOARM=$GOARM go build -v -o webhook \
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
