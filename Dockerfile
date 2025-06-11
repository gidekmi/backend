# Render.com için optimize edilmiş Dockerfile
FROM golang:1.21-alpine AS builder

# Gerekli paketleri yükle
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

# Go mod dosyalarını kopyala ve bağımlılıkları indir
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Kaynak kodunu kopyala
COPY . .

# Binary'yi build et (statik linking)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.version=1.0.0 -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -a -installsuffix cgo \
    -o bin/server \
    ./cmd/server

# Production stage - minimal image
FROM alpine:latest

# Güvenlik ve utility paketleri
RUN apk --no-cache add ca-certificates tzdata curl \
    && adduser -D -s /bin/sh appuser

# Timezone ayarla
ENV TZ=Europe/Istanbul

WORKDIR /app

# Built binary'yi kopyala
COPY --from=builder /app/bin/server .

# Binary'ye execute permission ver
RUN chmod +x server

# appuser'a ownership ver
RUN chown appuser:appuser server

# Non-root user olarak çalıştır
USER appuser

# Health check ekle
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8080}/health || exit 1

# Port expose et (Render dinamik port kullanır)
EXPOSE 8080

# Uygulamayı çalıştır
CMD ["./server"]