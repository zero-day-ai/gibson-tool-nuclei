# Multi-stage Dockerfile for nuclei tool
#
# Stage 1: Download nuclei binary from ProjectDiscovery releases
# Stage 2: Build Go wrapper binary
# Stage 3: Runtime alpine image with non-root user
#
# Build: docker build -t nuclei-tool .
# Run: docker run -p 50051:50051 -p 8080:8080 nuclei-tool

# ============================================================================
# Stage 1: Downloader - Download nuclei binary and templates
# ============================================================================
FROM alpine:3.21 AS downloader

# Install download dependencies
RUN apk add --no-cache wget unzip

# Download nuclei binary from ProjectDiscovery releases
ARG NUCLEI_VERSION=3.3.7
RUN wget -qO /tmp/nuclei.zip \
    "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" && \
    unzip /tmp/nuclei.zip -d /tmp && \
    chmod +x /tmp/nuclei && \
    rm -f /tmp/nuclei.zip

# Download nuclei templates using the correct flag syntax
# The -ud flag sets the template directory, -ut triggers the update
ENV HOME=/tmp/nuclei-home
RUN mkdir -p /tmp/nuclei-home && /tmp/nuclei -update-templates -ud /tmp/nuclei-home/nuclei-templates || \
    echo "WARNING: template download failed, templates will be fetched at runtime"

# ============================================================================
# Stage 2: Builder - Build Go wrapper binary
# ============================================================================
FROM golang:1.25-alpine AS builder

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -a -installsuffix cgo \
    -ldflags '-extldflags "-static"' \
    -o nuclei-tool ./cmd

# ============================================================================
# Stage 3: Runtime - Alpine with non-root user
# ============================================================================
FROM alpine:3.21

# Install runtime dependencies
# - ca-certificates: TLS certificate verification
# - tzdata: Timezone data for proper timestamp handling
# - wget: Health check endpoint verification
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    wget

# Create non-root user gibson with UID/GID 1000
RUN addgroup -g 1000 gibson && \
    adduser -D -u 1000 -G gibson -h /home/gibson -s /bin/sh gibson

# Copy nuclei binary from downloader stage
COPY --from=downloader /tmp/nuclei /usr/local/bin/nuclei

# Copy nuclei templates from downloader stage (if download succeeded)
COPY --from=downloader /tmp/nuclei-home/ /home/gibson/.config/nuclei/

# Copy the Go wrapper binary from builder stage
COPY --from=builder /build/nuclei-tool /usr/local/bin/nuclei-tool

# Ensure binaries are executable
RUN chmod +x /usr/local/bin/nuclei /usr/local/bin/nuclei-tool

# Set ownership of templates and working directory to gibson user
RUN chown -R gibson:gibson /home/gibson

# Change ownership of wrapper binary to gibson user
RUN chown gibson:gibson /usr/local/bin/nuclei-tool

# Create working directory for the tool
WORKDIR /home/gibson

# Expose gRPC port for tool service
EXPOSE 50051

# Expose health port for Kubernetes probes
EXPOSE 8080

# Health check using wget to verify the health endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/healthz || exit 1

# Run as non-root user
USER gibson

# Set the entrypoint to the Go wrapper (not /usr/local/bin/nuclei)
ENTRYPOINT ["/usr/local/bin/nuclei-tool"]
