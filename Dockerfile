# Multi-stage Dockerfile for nuclei tool

# Stage 1: Build the Go wrapper
FROM golang:1.25-alpine AS builder

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build static binary (Redis worker mode)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o nuclei-tool ./cmd/worker

# Stage 2: Runtime image
FROM kalilinux/kali-rolling:latest

# Install nuclei and dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    unzip \
    ca-certificates \
    procps && \
    wget -qO /tmp/nuclei.zip https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip && \
    unzip /tmp/nuclei.zip -d /tmp && \
    mv /tmp/nuclei /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && \
    rm -rf /tmp/* && \
    apt-get remove -y wget unzip && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Update nuclei templates
RUN nuclei -update-templates

# Copy the static binary from builder
COPY --from=builder /build/nuclei-tool /usr/local/bin/nuclei-tool

# Expose gRPC port
EXPOSE 50051

# Set the entrypoint to the Go wrapper (not /usr/local/bin/nuclei)
ENTRYPOINT ["/usr/local/bin/nuclei-tool"]
