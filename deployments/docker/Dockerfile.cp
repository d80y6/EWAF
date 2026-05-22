# Build stage
FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o sentinel-cp ./cmd/control-plane/main.go

# Production stage
FROM alpine:latest
WORKDIR /root/
COPY --from=builder /app/sentinel-cp .
EXPOSE 8081
CMD ["./sentinel-cp"]
