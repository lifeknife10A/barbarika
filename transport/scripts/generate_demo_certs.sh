#!/usr/bin/env bash
set -euo pipefail

# DEMO ONLY: creates a short-lived, self-signed local CA and leaf certificates.
# This is not production PKI and must not be added to a system-wide trust store.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TRANSPORT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
CERT_DIR="${TRANSPORT_DIR}/certs"

if [[ "${1:-}" == "--force" ]]; then
  FORCE=1
  shift
else
  FORCE=0
fi

if [[ $# -ne 0 ]]; then
  echo "Usage: $0 [--force]" >&2
  exit 2
fi

readonly CA_KEY="${CERT_DIR}/demo-ca.key"
readonly CA_CERT="${CERT_DIR}/demo-ca.crt"
readonly SERVER_KEY="${CERT_DIR}/demo-server.key"
readonly SERVER_CERT="${CERT_DIR}/demo-server.crt"
readonly CLIENT_KEY="${CERT_DIR}/demo-client.key"
readonly CLIENT_CERT="${CERT_DIR}/demo-client.crt"
readonly OUTPUTS=(
  "${CA_KEY}" "${CA_CERT}"
  "${SERVER_KEY}" "${SERVER_CERT}"
  "${CLIENT_KEY}" "${CLIENT_CERT}"
)

if [[ ${FORCE} -eq 0 ]]; then
  for output in "${OUTPUTS[@]}"; do
    if [[ -e "${output}" ]]; then
      echo "Refusing to overwrite existing demo certificates. Use --force to rotate them." >&2
      exit 1
    fi
  done
fi

mkdir -p "${CERT_DIR}"
umask 077

TEMP_DIR="$(mktemp -d "${CERT_DIR}/.demo-cert-generation.XXXXXX")"
cleanup() {
  rm -rf -- "${TEMP_DIR}"
}
trap cleanup EXIT

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "${CA_KEY}"
openssl req -new -x509 -sha256 -days 30 \
  -key "${CA_KEY}" \
  -config "${CERT_DIR}/ca.cnf" \
  -out "${CA_CERT}"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${SERVER_KEY}"
openssl req -new -sha256 \
  -key "${SERVER_KEY}" \
  -config "${CERT_DIR}/server.cnf" \
  -out "${TEMP_DIR}/server.csr"
openssl x509 -req -sha256 -days 30 -set_serial 0x1001 \
  -in "${TEMP_DIR}/server.csr" \
  -CA "${CA_CERT}" \
  -CAkey "${CA_KEY}" \
  -extfile "${CERT_DIR}/server.cnf" \
  -extensions v3_server \
  -out "${SERVER_CERT}"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${CLIENT_KEY}"
openssl req -new -sha256 \
  -key "${CLIENT_KEY}" \
  -config "${CERT_DIR}/client.cnf" \
  -out "${TEMP_DIR}/client.csr"
openssl x509 -req -sha256 -days 30 -set_serial 0x1002 \
  -in "${TEMP_DIR}/client.csr" \
  -CA "${CA_CERT}" \
  -CAkey "${CA_KEY}" \
  -extfile "${CERT_DIR}/client.cnf" \
  -extensions v3_client \
  -out "${CLIENT_CERT}"

chmod 600 "${CA_KEY}" "${SERVER_KEY}" "${CLIENT_KEY}"
chmod 644 "${CA_CERT}" "${SERVER_CERT}" "${CLIENT_CERT}"

openssl verify -CAfile "${CA_CERT}" -purpose sslserver "${SERVER_CERT}"
openssl verify -CAfile "${CA_CERT}" -purpose sslclient "${CLIENT_CERT}"

echo "Generated DEMO-ONLY mTLS identities in ${CERT_DIR} (valid for 30 days)."
echo "Do not use these files as production PKI or install the CA system-wide."
