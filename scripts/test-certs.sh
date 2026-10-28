#!/usr/bin/env bash
# Generates a throwaway CA and a server certificate for "localhost" (no IP SANs, so
# connecting by 127.0.0.1 exercises the name-mismatch path).
set -euo pipefail
DIR="${1:-$(cd "$(dirname "$0")/.." && pwd)/target/test-ldap/certs}"
mkdir -p "$DIR"
cd "$DIR"
[[ -f server.pem && -f ca.pem ]] && exit 0
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=LdapTui Test CA" \
  -keyout ca.key -out ca.pem 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" -keyout server.key -out server.csr 2>/dev/null
printf "subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n" > ext.cnf
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 3650 \
  -extfile ext.cnf -out server.pem 2>/dev/null
# A second, unrelated CA for "untrusted" tests.
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=Other CA" \
  -keyout other-ca.key -out other-ca.pem 2>/dev/null
chmod 600 *.key
echo "certs in $DIR"
