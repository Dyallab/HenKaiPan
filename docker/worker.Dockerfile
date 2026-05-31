# Stage 1: Build worker binary
FROM golang:1.26-alpine AS builder
ARG VERSION=dev
ARG BUILD_DATE=unknown

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build \
    -ldflags "-X aspm/internal/handlers.Version=$VERSION -X aspm/internal/handlers.BuildDate=$BUILD_DATE" \
    -o /worker ./cmd/worker

# Stage 2: Install scanner binaries
# All scanner versions pinned in one layer for deterministic Docker caching.
# With cache-from: type=gha, this layer is reused across builds when versions don't change.
FROM alpine:3.22 AS scanners

ARG TRIVY_VERSION=0.60.0
ARG GITLEAKS_VERSION=8.30.1
ARG GRYPE_VERSION=0.90.0
ARG OSV_SCANNER_VERSION=2.0.0
ARG TRUFFLEHOG_VERSION=3.95.2
ARG TFSEC_VERSION=1.28.13
ARG KICS_VERSION=2.1.20
ARG NUCLEI_VERSION=3.8.0
ARG GOSEC_VERSION=2.26.1

RUN apk add --no-cache \
    ca-certificates curl bash git unzip python3 py3-pip && \
    # Semgrep + Checkov (Python scanners)
    pip install --no-cache-dir --break-system-packages semgrep checkov && \
    # ── Binary scanners ──
    # Trivy (SCA)
    curl -sL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" | tar xz -C /tmp && \
    mv /tmp/trivy /usr/local/bin/ && \
    # Gitleaks (Secrets)
    curl -sL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" | tar xz && \
    mv gitleaks /usr/local/bin/ && \
    # Grype (SCA)
    curl -sL "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz" | tar xz -C /tmp && \
    mv /tmp/grype /usr/local/bin/ && \
    # OSV-Scanner (SCA)
    curl -sLo /usr/local/bin/osv-scanner "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64" && \
    chmod +x /usr/local/bin/osv-scanner && \
    # TruffleHog (Secrets)
    curl -sL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz" | tar xz && \
    mv trufflehog /usr/local/bin/ && \
    # TFSec (IaC)
    curl -sLo /usr/local/bin/tfsec "https://github.com/aquasecurity/tfsec/releases/download/v${TFSEC_VERSION}/tfsec-linux-amd64" && \
    chmod +x /usr/local/bin/tfsec && \
    # KICS (IaC)
    curl -sL "https://github.com/Checkmarx/kics/releases/download/v${KICS_VERSION}/kics_${KICS_VERSION}_linux_amd64.tar.gz" | tar xz -C /tmp && \
    mv /tmp/kics /usr/local/bin/ && \
    # Nuclei (DAST)
    curl -sL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -o /tmp/nuclei.zip && \
    unzip -o /tmp/nuclei.zip -d /tmp && \
    mv /tmp/nuclei /usr/local/bin/ && \
    rm /tmp/nuclei.zip && \
    # Gosec (SAST)
    curl -sL "https://github.com/securego/gosec/releases/download/v${GOSEC_VERSION}/gosec_${GOSEC_VERSION}_linux_amd64.tar.gz" | tar xz && \
    mv gosec /usr/local/bin/

# Stage 3: Final minimal image
FROM alpine:3.22

# Install runtime dependencies (python3 needed for semgrep)
RUN apk add --no-cache ca-certificates git python3

# Copy worker binary from builder
COPY --from=builder /worker /worker

# Copy scanner binaries from scanners stage
COPY --from=scanners /usr/bin/semgrep /usr/local/bin/semgrep
COPY --from=scanners /usr/bin/checkov /usr/local/bin/checkov
COPY --from=scanners /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=scanners /usr/local/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=scanners /usr/local/bin/grype /usr/local/bin/grype
COPY --from=scanners /usr/local/bin/osv-scanner /usr/local/bin/osv-scanner
COPY --from=scanners /usr/local/bin/trufflehog /usr/local/bin/trufflehog
COPY --from=scanners /usr/local/bin/tfsec /usr/local/bin/tfsec
COPY --from=scanners /usr/local/bin/kics /usr/local/bin/kics
COPY --from=scanners /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=scanners /usr/local/bin/gosec /usr/local/bin/gosec

# Copy Python runtime for semgrep
COPY --from=scanners /usr/lib/python3.12 /usr/lib/python3.12
COPY --from=scanners /usr/bin/python3* /usr/bin/

# Create pysemgrep wrapper
RUN printf '#!/bin/sh\nexec python3 -m semgrep.console_scripts.pysemgrep "$@"' > /usr/local/bin/pysemgrep && \
    chmod +x /usr/local/bin/pysemgrep


# Create non-root user and group
RUN addgroup -g 1000 worker && \
    adduser -D -u 1000 -G worker worker

# Set ownership and permissions
RUN chown -R worker:worker /worker && \
    chmod +x /worker

# Switch to non-root user
USER worker:worker

WORKDIR /

ENTRYPOINT ["/worker"]
