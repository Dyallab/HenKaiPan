#!/bin/bash
#
# HenKaiPan ASPM License Key Generator
# Generates free license keys for beta users.
#
# Usage: ./generate-license.sh <email> [days]
#   email: User email address
#   days:  License validity in days (default: 365)
#

set -e

EMAIL="${1:-}"
DAYS="${2:-365}"

if [ -z "$EMAIL" ]; then
    echo "Usage: $0 <email> [days]"
    echo "  email: User email address"
    echo "  days:  License validity in days (default: 365)"
    exit 1
fi

# Calculate expiry timestamp
EXPIRY=$(date -d "+${DAYS} days" +%s)

# Create license payload
PAYLOAD=$(cat <<EOF
{"email":"$EMAIL","expiry":$EXPIRY,"features":["self-hosted","unlimited-projects","email-support"]}
EOF
)

# Generate signature (using same secret as in handlers/license.go)
SECRET="aspm-license-secret"
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET" -binary | base64 -w 0)

# Combine payload and signature
LICENSE=$(echo -n "$PAYLOAD.$SIGNATURE" | base64 -w 0)

echo ""
echo "HenKaiPan ASPM License Key"
echo "=========================="
echo ""
echo "Email:  $EMAIL"
echo "Valid:  $DAYS days (expires $(date -d "@$EXPIRY" +%Y-%m-%d))"
echo ""
echo "License Key:"
echo "------------"
echo "$LICENSE"
echo ""
echo "Set this key as LICENSE_KEY environment variable:"
echo "  export LICENSE_KEY=$LICENSE"
echo ""
echo "Or add to .env file:"
echo "  LICENSE_KEY=$LICENSE"
echo ""
