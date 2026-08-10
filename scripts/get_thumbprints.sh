#!/usr/bin/env bash

set -euo pipefail

readonly DEFAULT_OUTPUT_FILE="thumbprints.txt"

usage() {
    cat <<EOF
Usage: $0 [--insecure] <oidc-endpoint> [output-file]

Fetch X.509 certificates from an OIDC discovery document or JWKS endpoint and
write their SHA-1 thumbprints to a file.

Arguments:
  oidc-endpoint  OIDC discovery document or direct JWKS endpoint
  output-file    Destination file (default: ${DEFAULT_OUTPUT_FILE})

Options:
  -k, --insecure  Disable TLS certificate verification (testing only)
  -h, --help      Show this help message

Examples:
  $0 https://keycloak.example.com/realms/myrealm/.well-known/openid-configuration
  $0 https://token.actions.githubusercontent.com/.well-known/jwks
  $0 --insecure https://keycloak.example.com/realms/myrealm/.well-known/openid-configuration thumbprints.txt
EOF
}

die() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

validate_url() {
    case "$1" in
        http://* | https://*) ;;
        *) die "Expected an HTTP(S) URL, got: $1" ;;
    esac
}

INSECURE=false
POSITIONAL=()

while (($# > 0)); do
    case "$1" in
        -k | --insecure)
            INSECURE=true
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        --)
            shift
            while (($# > 0)); do
                POSITIONAL+=("$1")
                shift
            done
            break
            ;;
        -*)
            usage >&2
            die "Unknown option: $1"
            ;;
        *)
            POSITIONAL+=("$1")
            ;;
    esac
    shift
done

if ((${#POSITIONAL[@]} < 1 || ${#POSITIONAL[@]} > 2)); then
    usage >&2
    exit 1
fi

readonly ENDPOINT="${POSITIONAL[0]}"
readonly OUTPUT_FILE="${POSITIONAL[1]:-${DEFAULT_OUTPUT_FILE}}"

validate_url "$ENDPOINT"

for command_name in curl jq openssl awk mktemp; do
    require_command "$command_name"
done

OUTPUT_DIR=$(dirname -- "$OUTPUT_FILE")
OUTPUT_BASE=$(basename -- "$OUTPUT_FILE")
[[ -d "$OUTPUT_DIR" ]] || die "Output directory does not exist: $OUTPUT_DIR"
[[ ! -d "$OUTPUT_FILE" ]] || die "Output path is a directory: $OUTPUT_FILE"

TEMP_DIR=""
TEMP_OUTPUT=""

cleanup() {
    if [[ -n "$TEMP_OUTPUT" && -f "$TEMP_OUTPUT" ]]; then
        rm -f -- "$TEMP_OUTPUT"
    fi
    if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then
        rm -rf -- "$TEMP_DIR"
    fi
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM

TEMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/get_thumbprints.XXXXXX") || \
    die "Could not create a temporary directory"
TEMP_OUTPUT=$(mktemp "${OUTPUT_DIR}/.${OUTPUT_BASE}.tmp.XXXXXX") || \
    die "Could not create a temporary file in: $OUTPUT_DIR"

CURL_ARGS=(
    --fail
    --silent
    --show-error
    --location
    --connect-timeout 10
    --max-time 30
    --header "Accept: application/json"
)

if [[ "$INSECURE" == true ]]; then
    CURL_ARGS+=(--insecure)
    printf 'Warning: TLS certificate verification is disabled.\n' >&2
fi

fetch_json() {
    local url=$1
    local destination=$2
    local description=$3

    if ! curl "${CURL_ARGS[@]}" --output "$destination" "$url"; then
        die "Could not fetch ${description}: $url"
    fi

    if ! jq -e . "$destination" >/dev/null 2>&1; then
        die "${description} did not return valid JSON: $url"
    fi
}

printf 'Processing endpoint: %s\n' "$ENDPOINT"

ENDPOINT_JSON="${TEMP_DIR}/endpoint.json"
JWKS_JSON="${TEMP_DIR}/jwks.json"
fetch_json "$ENDPOINT" "$ENDPOINT_JSON" "OIDC endpoint"

if jq -e '.jwks_uri | type == "string" and length > 0' "$ENDPOINT_JSON" >/dev/null 2>&1; then
    JWKS_URI=$(jq -er '.jwks_uri' "$ENDPOINT_JSON")
    validate_url "$JWKS_URI"
    printf 'OIDC discovery document detected.\n'
    printf 'Discovered JWKS URI: %s\n' "$JWKS_URI"
    fetch_json "$JWKS_URI" "$JWKS_JSON" "JWKS endpoint"
elif jq -e '.keys | type == "array"' "$ENDPOINT_JSON" >/dev/null 2>&1; then
    JWKS_URI="$ENDPOINT"
    printf 'Direct JWKS endpoint detected.\n'
    cp -- "$ENDPOINT_JSON" "$JWKS_JSON"
else
    die "Endpoint is neither an OIDC discovery document nor a JWKS document"
fi

CERTIFICATES="${TEMP_DIR}/certificates.txt"
if ! jq -r '
    .keys[]?
    | .x5c[]?
    | select(type == "string" and length > 0)
' "$JWKS_JSON" >"$CERTIFICATES"; then
    die "Could not extract certificates from the JWKS document"
fi

if [[ ! -s "$CERTIFICATES" ]]; then
    printf 'Error: No X.509 certificates (x5c entries) found in the JWKS document.\n' >&2
    printf 'Available keys:\n' >&2
    jq '
        .keys[]?
        | select(type == "object")
        | {
            kty: .kty,
            use: .use,
            kid: .kid,
            has_x5c: has("x5c"),
            has_x5t: has("x5t")
        }
    ' "$JWKS_JSON" >&2
    exit 1
fi

RAW_THUMBPRINTS="${TEMP_DIR}/thumbprints.txt"
: >"$RAW_THUMBPRINTS"

CERTIFICATE_INDEX=0
while IFS= read -r certificate; do
    CERTIFICATE_INDEX=$((CERTIFICATE_INDEX + 1))
    CERTIFICATE_FILE="${TEMP_DIR}/certificate-${CERTIFICATE_INDEX}.pem"

    {
        printf '%s\n' '-----BEGIN CERTIFICATE-----'
        printf '%s\n' "$certificate"
        printf '%s\n' '-----END CERTIFICATE-----'
    } >"$CERTIFICATE_FILE"

    if ! fingerprint=$(openssl x509 \
        -in "$CERTIFICATE_FILE" \
        -noout \
        -fingerprint \
        -sha1 2>/dev/null); then
        die "JWKS x5c entry ${CERTIFICATE_INDEX} is not a valid X.509 certificate"
    fi

    fingerprint=${fingerprint#*=}
    fingerprint=${fingerprint//:/}
    fingerprint=${fingerprint//$'\r'/}

    if [[ ! "$fingerprint" =~ ^[[:xdigit:]]{40}$ ]]; then
        die "OpenSSL returned an invalid SHA-1 fingerprint for x5c entry ${CERTIFICATE_INDEX}"
    fi

    printf '%s\n' "$fingerprint" | awk '{ print toupper($0) }' >>"$RAW_THUMBPRINTS"
done <"$CERTIFICATES"

# A certificate can appear in more than one JWK. Preserve discovery order while
# removing duplicates so the resulting IAM thumbprint list is deterministic.
awk '!seen[$0]++' "$RAW_THUMBPRINTS" >"$TEMP_OUTPUT"

THUMBPRINT_COUNT=$(awk 'END { print NR }' "$TEMP_OUTPUT")
mv -- "$TEMP_OUTPUT" "$OUTPUT_FILE"
TEMP_OUTPUT=""

printf 'Saved %d unique certificate thumbprint(s) to: %s\n' \
    "$THUMBPRINT_COUNT" "$OUTPUT_FILE"
printf 'Contents:\n'
cat -- "$OUTPUT_FILE"
