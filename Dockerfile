FROM golang:1.21-alpine AS builder

# Install dependencies
RUN apk add --no-cache \
    git \
    make \
    gcc \
    musl-dev

# Create and set working directory
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN go build -o acva main.go

# Create a minimal runtime image
FROM alpine:3.18

# Install necessary packages
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    chromium \
    chromium-chromedriver

# Create non-root user
RUN adduser -D -u 1000 acva

# Set working directory
WORKDIR /app

# Copy built binary
COPY --from=builder /app/acva .
COPY --from=builder /app/config.yaml ./config/
COPY --from=builder /app/wordlists ./wordlists/

# Create necessary directories
RUN mkdir -p reports logs && \
    chown -R acva:acva /app

# Switch to non-root user
USER acva

# Expose port for API mode
EXPOSE 8080

# Set entrypoint
ENTRYPOINT ["./acva"]
