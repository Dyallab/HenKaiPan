# Stage 1: Build worker binary
FROM golang:1.26-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /worker ./cmd/worker

# Stage 2: Install scanner binaries
FROM alpine:3.22 AS scanners

# Install base dependencies
RUN apk add --no-cache \
    ca-certificates \
    curl \
    bash \
    git \
    python3

# Install Python-based scanners in isolated venv
RUN python3 -m venv /opt/scanner-venv && \
    . /opt/scanner-venv/bin/activate && \
    pip install --no-cache-dir semgrep checkov

# Install Trivy (SCA)
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install Gitleaks (Secrets)
RUN curl -sL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_amd64.tar.gz | tar xz && \
    mv gitleaks /usr/local/bin/

# Install Grype (SCA)
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install OSV-Scanner (SCA)
RUN curl -sL https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64.tar.gz | tar xz && \
    mv osv-scanner /usr/local/bin/

# Install TruffleHog (Secrets)
RUN curl -sL https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_linux_amd64.tar.gz | tar xz && \
    mv trufflehog /usr/local/bin/

# Install TFSec (IaC)
RUN curl -sL https://github.com/aquasecurity/tfsec/releases/latest/download/tfsec-linux-amd64 | install /usr/local/bin/tfsec

# Install KICS (IaC)
RUN curl -sL https://github.com/Checkmarx/kics/releases/latest/download/kics_linux_amd64 | install /usr/local/bin/kics

# Install Nuclei (DAST)
RUN curl -sL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip -o nuclei.zip && \
    unzip nuclei.zip && \
    mv nuclei /usr/local/bin/ && \
    rm nuclei.zip

# Install Gosec (SAST)
RUN curl -sL https://github.com/securego/gosec/releases/latest/download/gosec_latest_linux_amd64.tar.gz | tar xz && \
    mv gosec /usr/local/bin/

# Stage 3: Final minimal image
FROM alpine:3.22

# Install only runtime dependencies
RUN apk add --no-cache ca-certificates git

# Copy worker binary from builder
COPY --from=builder /worker /worker

# Copy scanner binaries from scanners stage
COPY --from=scanners /opt/scanner-venv /opt/scanner-venv
COPY --from=scanners /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=scanners /usr/local/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=scanners /usr/local/bin/grype /usr/local/bin/grype
COPY --from=scanners /usr/local/bin/osv-scanner /usr/local/bin/osv-scanner
COPY --from=scanners /usr/local/bin/trufflehog /usr/local/bin/trufflehog
COPY --from=scanners /usr/local/bin/tfsec /usr/local/bin/tfsec
COPY --from=scanners /usr/local/bin/kics /usr/local/bin/kics
COPY --from=scanners /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=scanners /usr/local/bin/gosec /usr/local/bin/gosec

ENV PATH="/opt/scanner-venv/bin:$PATH"

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
