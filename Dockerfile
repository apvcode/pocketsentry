FROM golang:1.22-alpine AS builder

WORKDIR /app

# Download Go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY . .

# Build the statically linked Go binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o pocketsentry .

# ---------------------------------------------------
# Stage 2: Final lightweight image
# ---------------------------------------------------
FROM alpine:latest

# Add CA certificates so Webhooks (Telegram/Discord) can use HTTPS securely
RUN apk --no-cache add ca-certificates

WORKDIR /app

# Copy the built binary from the builder stage
COPY --from=builder /app/pocketsentry .

# Create a directory for the SQLite database so it can be mounted as a volume
RUN mkdir -p /data

EXPOSE 8080

# Run the binary, pointing the database to the /data directory
ENTRYPOINT ["./pocketsentry", "--db", "/data/pocketsentry.db"]
