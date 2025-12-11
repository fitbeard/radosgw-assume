#!/bin/bash

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "Usage: $0 <oidc-endpoint> [output-file]"
    echo ""
    echo "Examples:"
    echo "  $0 https://keycloak.example.com/realms/myrealm/.well-known/openid-configuration"
    echo "  $0 https://token.actions.githubusercontent.com/.well-known/jwks"
    echo "  $0 https://keycloak.example.com/realms/myrealm/.well-known/openid-configuration thumbprints.txt"
    echo ""
    echo "The script auto-detects whether the endpoint is:"
    echo "  - OIDC configuration endpoint (.well-known/openid-configuration)"
    echo "  - Direct JWKS endpoint (.well-known/jwks)"
    exit 1
fi

ENDPOINT="$1"
OUTPUT_FILE="${2:-thumbprints.txt}"

echo "Processing endpoint: $ENDPOINT"

# Determine if this is a direct JWKS endpoint or OIDC config endpoint
if [[ "$ENDPOINT" == *"/.well-known/jwks" ]]; then
    # Direct JWKS endpoint (like GitHub Actions)
    JWKS_URI="$ENDPOINT"
    echo "Direct JWKS endpoint detected"
elif [[ "$ENDPOINT" == *"/.well-known/openid-configuration" ]]; then
    # OIDC configuration endpoint (like Keycloak)
    echo "OIDC configuration endpoint detected, discovering JWKS URI..."
    
    JWKS_URI=$(curl -k -s \
         -X GET \
         -H "Content-Type: application/x-www-form-urlencoded" \
         "$ENDPOINT" \
         | jq -r '.jwks_uri')

    # Check if JWKS_URI was found
    if [ -z "$JWKS_URI" ] || [ "$JWKS_URI" == "null" ]; then
        echo "Error: Could not retrieve 'jwks_uri' from OIDC configuration."
        exit 1
    fi
    
    echo "Discovered JWKS URI: $JWKS_URI"
else
    echo "Error: Endpoint must be either:"
    echo "  - OIDC config: .../well-known/openid-configuration"
    echo "  - Direct JWKS: .../well-known/jwks"
    exit 1
fi

# Retrieve all certificate keys from JWKS
KEYS=$(curl -k -s \
     -X GET \
     -H "Accept: application/json" \
     "$JWKS_URI" 2>/dev/null \
     | jq -r '.keys[].x5c[]?')

if [ -z "$KEYS" ]; then
    echo "Error: No certificates found in JWKS endpoint."
    echo "This might be expected if the provider uses other key types (RSA/EC without x5c)."
    
    # Try to show what keys are available
    echo ""
    echo "Available keys in JWKS:"
    curl -k -s "$JWKS_URI" | jq '.keys[] | {kty: .kty, use: .use, kid: .kid, has_x5c: (has("x5c")), has_x5t: (has("x5t"))}'
    exit 1
fi

echo ""
echo "Assembling Certificates from JWKS..."

# Clear output file if it exists
rm -f "$OUTPUT_FILE"

# Process each certificate dynamically
INDEX=1
for KEY in $KEYS; do
    CERT_FILE="certificate$INDEX.crt"
    echo '-----BEGIN CERTIFICATE-----' > "$CERT_FILE"
    echo -E "$KEY" >> "$CERT_FILE"
    echo '-----END CERTIFICATE-----' >> "$CERT_FILE"
    
    echo "Certificate $INDEX:"
    echo "$(cat "$CERT_FILE")"
    echo ""

    echo "Generating thumbprint for certificate $INDEX..."
    PRETHUMBPRINT=$(openssl x509 -in "$CERT_FILE" -fingerprint -noout | awk '{ print substr($0, 18) }')

    echo "${PRETHUMBPRINT//:/}" >> "$OUTPUT_FILE"

    # Clean up temp file
    rm "$CERT_FILE"

    ((INDEX++))
done

echo "Certificate thumbprints saved to: $OUTPUT_FILE"
echo ""
echo "Contents:"
cat "$OUTPUT_FILE"
