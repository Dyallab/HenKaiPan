FROM golang:1.26-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /worker ./cmd/worker

FROM alpine:3.21
RUN apk add --no-cache ca-certificates git docker-cli
COPY --from=builder /worker /worker
CMD ["/worker"]
