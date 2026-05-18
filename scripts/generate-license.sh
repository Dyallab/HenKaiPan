#!/bin/bash
#
# HenKaiPan ASPM License Key Generator
#
# Usage:
#   ./generate-license.sh <email> [days] [-f features]
#
# Arguments:
#   email     User email address (required)
#   days      License validity in days (default: 365)
#   -f        Comma-separated feature list (default: see below)
#
# Examples:
#   ./generate-license.sh admin@example.com 365
#   ./generate-license.sh user@example.com 90 -f "scheduling,policies,compliance"

set -e

EMAIL="${1:-}"
DAYS="${2:-365}"
FEATURES=""

# Parse flags
shift 2 2>/dev/null || true
while [ $# -gt 0 ]; do
    case "$1" in
        -f|--features)
            FEATURES="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

if [ -z "$EMAIL" ]; then
    echo "Usage: $0 <email> [days] [-f features]"
    echo ""
    echo "  email    User email address (required)"
    echo "  days     License validity in days (default: 365)"
    echo "  -f       Comma-separated features (default: none)"
    echo ""
    echo "Available features:"
    echo "  scheduling, policies, compliance, integrations, ai-remediation, reports,"
    echo "  audit-log, risk-acceptance, teams, comments, email-notifications"
    echo ""
    echo "Examples:"
    echo "  $0 admin@example.com 365"
    echo "  $0 admin@example.com 365 -f \"scheduling,policies,compliance\""
    exit 1
fi

# Build features JSON arrays
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

# Generate HMAC signature (binary), concatenate payload + "." + signature, then base64 encode
LICENSE=$( { echo -n "$PAYLOAD"; printf '.'; echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "henkaipan-ecf5c8fb-dd0c-4f0c-b5d2-eee7719741ad" -binary; } | base64 -w 0)

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
echo "IMPORTANT: This key is signed with the embedded binary secret."
echo "Set this in the target instance .env:"
echo "  LICENSE_KEY=$LICENSE"
echo ""
