# Stage 1: Build frontend
FROM node:24-alpine AS frontend
WORKDIR /app/frontend
COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN corepack enable && pnpm install --frozen-lockfile --ignore-scripts && pnpm rebuild esbuild sharp
COPY frontend/ .
RUN pnpm build

# Stage 2: Build Go API
FROM golang:1.26-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /app/frontend/dist ./cmd/api/frontend-dist
RUN go build -tags embed_frontend -o /api ./cmd/api

# Stage 3: Runtime
FROM alpine:3.22.4
RUN apk add --no-cache ca-certificates
COPY --from=builder /api /api
EXPOSE 8080
CMD ["/api"]
