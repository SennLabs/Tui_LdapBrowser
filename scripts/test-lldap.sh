#!/usr/bin/env bash
# Starts/stops a throwaway LLDAP for integration tests. No Docker, no root.
#   scripts/test-lldap.sh start   # ldap://localhost:13890, ldaps://localhost:16360
#   scripts/test-lldap.sh stop
set -euo pipefail
VERSION="v0.6.3"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASE="$ROOT/target/test-ldap"
DIR="$BASE/lldap"
BIN_DIR="$BASE/lldap-$VERSION"
CERTS="$BASE/certs"
LDAP_PORT="${LLDAP_TEST_LDAP_PORT:-13890}"
LDAPS_PORT="${LLDAP_TEST_LDAPS_PORT:-16360}"
HTTP_PORT="${LLDAP_TEST_HTTP_PORT:-17171}"
ADMIN_PW="adminpass"
URL="http://localhost:$HTTP_PORT"

stop() {
  if [[ -f "$DIR/lldap.pid" ]]; then
    kill "$(cat "$DIR/lldap.pid")" 2>/dev/null || true
    sleep 0.5
  fi
  rm -rf "$DIR"
}

fetch() {
  [[ -x "$BIN_DIR/lldap" ]] && return
  mkdir -p "$BIN_DIR"
  curl -fsSL "https://github.com/lldap/lldap/releases/download/$VERSION/amd64-lldap.tar.gz" \
    | tar xz -C "$BIN_DIR" --strip-components=1
}

gql() { # gql TOKEN JSON
  curl -fsS "$URL/api/graphql" -H "Authorization: Bearer $1" -H "Content-Type: application/json" -d "$2"
}

start() {
  stop
  fetch
  "$ROOT/scripts/test-certs.sh" "$CERTS" >/dev/null
  mkdir -p "$DIR"
  (
    cd "$BIN_DIR"
    LLDAP_JWT_SECRET="test-jwt-secret-not-for-production" \
    LLDAP_KEY_SEED="test-key-seed-not-for-production" \
    LLDAP_LDAP_BASE_DN="dc=example,dc=com" \
    LLDAP_LDAP_USER_PASS="$ADMIN_PW" \
    LLDAP_DATABASE_URL="sqlite://$DIR/users.db?mode=rwc" \
    LLDAP_LDAP_HOST=127.0.0.1 LLDAP_HTTP_HOST=127.0.0.1 \
    LLDAP_LDAP_PORT="$LDAP_PORT" LLDAP_HTTP_PORT="$HTTP_PORT" \
    LLDAP_LDAPS_OPTIONS__ENABLED=true LLDAP_LDAPS_OPTIONS__PORT="$LDAPS_PORT" \
    LLDAP_LDAPS_OPTIONS__CERT_FILE="$CERTS/server.pem" LLDAP_LDAPS_OPTIONS__KEY_FILE="$CERTS/server.key" \
    nohup ./lldap run > "$DIR/lldap.log" 2>&1 &
    echo $! > "$DIR/lldap.pid"
  )
  for _ in $(seq 100); do curl -fs "$URL/health" >/dev/null 2>&1 && break; sleep 0.1; done
  TOKEN=$(curl -fsS "$URL/auth/simple/login" -H "Content-Type: application/json" \
    -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PW\"}" | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])')
  for u in alice bob carol; do
    gql "$TOKEN" "{\"query\":\"mutation{createUser(user:{id:\\\"$u\\\",email:\\\"$u@example.com\\\",displayName:\\\"${u^} Example\\\",firstName:\\\"${u^}\\\",lastName:\\\"Example\\\"}){id}}\"}" >/dev/null
    "$BIN_DIR/lldap_set_password" --base-url "$URL" --admin-username admin --admin-password "$ADMIN_PW" \
      --username "$u" --password "${u}pass1234" >/dev/null
  done
  declare -A GID
  for g in staff admins; do
    GID[$g]=$(gql "$TOKEN" "{\"query\":\"mutation{createGroup(name:\\\"$g\\\"){id}}\"}" \
      | python3 -c 'import json,sys;print(json.load(sys.stdin)["data"]["createGroup"]["id"])')
  done
  for pair in alice:staff bob:staff alice:admins; do
    u=${pair%%:*}; g=${pair##*:}
    gql "$TOKEN" "{\"query\":\"mutation{addUserToGroup(userId:\\\"$u\\\",groupId:${GID[$g]}){ok}}\"}" >/dev/null
  done
  echo "lldap running: ldap://localhost:$LDAP_PORT  ldaps://localhost:$LDAPS_PORT  (uid=admin,ou=people,dc=example,dc=com / $ADMIN_PW)"
}

case "${1:-start}" in
  start) start ;;
  stop) stop ;;
  *) echo "usage: $0 start|stop"; exit 2 ;;
esac
