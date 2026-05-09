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
    unzip

# Install Semgrep + Checkov (need Python runtime)
RUN apk add --no-cache python3 py3-pip && \
    pip install --no-cache-dir --break-system-packages semgrep checkov

# Install Trivy (SCA)
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

ARG GITLEAKS_VERSION=8.30.1

# Install Gitleaks (Secrets)
RUN curl -sL https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz | tar xz && \
    mv gitleaks /usr/local/bin/

# Install Grype (SCA)
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install OSV-Scanner (SCA)
RUN curl -sLo /usr/local/bin/osv-scanner https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64 && \
    chmod +x /usr/local/bin/osv-scanner

ARG TRUFFLEHOG_VERSION=3.95.2

# Install TruffleHog (Secrets)
RUN curl -sL https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz -o trufflehog.tar.gz && \
    tar xzf trufflehog.tar.gz && \
    mv trufflehog /usr/local/bin/ && \
    rm trufflehog.tar.gz

# Install TFSec (IaC)
RUN curl -sLo /usr/local/bin/tfsec https://github.com/aquasecurity/tfsec/releases/latest/download/tfsec-linux-amd64 && \
    chmod +x /usr/local/bin/tfsec

ARG KICS_VERSION=2.1.20

# Install KICS (IaC)
RUN curl -sL https://github.com/Checkmarx/kics/releases/download/v${KICS_VERSION}/kics_${KICS_VERSION}_linux_amd64.tar.gz -o kics.tar.gz && \
    tar xzf kics.tar.gz -C /tmp && \
    mv /tmp/kics /usr/local/bin/ && \
    rm -f kics.tar.gz

ARG NUCLEI_VERSION=3.8.0
ARG GOSEC_VERSION=2.26.1

# Install Nuclei (DAST)
RUN curl -sL https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip -o nuclei.zip && \
    unzip -o nuclei.zip && \
    mv nuclei /usr/local/bin/ && \
    rm nuclei.zip

# Install Gosec (SAST)
RUN curl -sL https://github.com/securego/gosec/releases/download/v${GOSEC_VERSION}/gosec_${GOSEC_VERSION}_linux_amd64.tar.gz -o gosec.tar.gz && \
    tar xzf gosec.tar.gz && \
    mv gosec /usr/local/bin/ && \
    rm gosec.tar.gz

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
