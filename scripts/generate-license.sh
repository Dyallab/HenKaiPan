#!/bin/bash
#
# HenKaiPan ASPM License Key Generator
#
# Usage:
#   ./generate-license.sh <email> [days] [-f features] [-s secret]
#
# Arguments:
#   email     User email address (required)
#   days      License validity in days (default: 365)
#   -f        Comma-separated feature list (default: see below)
#   -s        Signing secret (required: set via -s or $LICENSE_SIGNING_SECRET)
#
# Examples:
#   ./generate-license.sh admin@example.com 365 -s "my-secret"
#   ./generate-license.sh user@example.com 90 -f "scheduling,policies,compliance" -s "my-secret"
#   LICENSE_SIGNING_SECRET=mysecret ./generate-license.sh user@example.com

set -e

EMAIL="${1:-}"
DAYS="${2:-365}"
FEATURES=""
SECRET="${LICENSE_SIGNING_SECRET:-}"

# Parse flags
shift 2 2>/dev/null || true
while [ $# -gt 0 ]; do
    case "$1" in
        -f|--features)
            FEATURES="$2"
            shift 2
            ;;
        -s|--secret)
            SECRET="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

if [ -z "$EMAIL" ]; then
    echo "Usage: $0 <email> [days] -s <secret> [-f features]"
    echo ""
    echo "  email    User email address (required)"
    echo "  days     License validity in days (default: 365)"
    echo "  -s       Signing secret (required: set via -s or \$LICENSE_SIGNING_SECRET env var)"
    echo "  -f       Comma-separated features (default: none)"
    echo ""
    echo "Available features:"
    echo "  scheduling, policies, compliance, integrations, ai-remediation, reports,"
    echo "  audit-log, risk-acceptance, teams, comments, email-notifications"
    echo ""
    echo "Examples:"
    echo "  $0 admin@example.com 365 -s \"my-secret\""
    echo "  $0 admin@example.com 365 -s \"my-secret\" -f \"scheduling,policies,compliance\""
    echo "  LICENSE_SIGNING_SECRET=mysecret $0 admin@example.com 365"
    exit 1
fi

if [ -z "$SECRET" ]; then
    echo "ERROR: Signing secret is required." >&2
    echo "Set it via -s <secret> or LICENSE_SIGNING_SECRET env var." >&2
    exit 1
fi

# Build features JSON array
if [ -n "$FEATURES" ]; then
    FEATURES_JSON="[\"$(echo "$FEATURES" | sed 's/,/","/g')\"]"
else
    FEATURES_JSON="[]"
fi

EXPIRY=$(date -d "+${DAYS} days" +%s)
PAYLOAD=$(cat <<EOF
{"email":"$EMAIL","expiry":$EXPIRY,"features":$FEATURES_JSON}
EOF
)

SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET" -binary | base64 -w 0)
LICENSE=$(echo -n "$PAYLOAD.$SIGNATURE" | base64 -w 0)

echo ""
echo "HenKaiPan ASPM License Key"
echo "=========================="
echo ""
echo "Email:    $EMAIL"
echo "Valid:    $DAYS days (expires $(date -d "@$EXPIRY" +%Y-%m-%d))"
echo "Features: ${FEATURES:-none}"
echo ""
echo "License Key:"
echo "------------"
echo "$LICENSE"
echo ""
echo "IMPORTANT: The LICENSE_SIGNING_SECRET used to generate this key"
echo "must be set in the target instance's environment. Without it,"
echo "the license key cannot be validated."
echo ""
echo "Set these in the target instance .env:"
echo "  LICENSE_KEY=$LICENSE"
echo "  LICENSE_SIGNING_SECRET=$SECRET"
echo ""
