#!/usr/bin/env bash
# Starts/stops a throwaway OpenLDAP (slapd) for integration tests. No Docker, no root.
#   scripts/test-slapd.sh start   # ldap://localhost:10389, ldaps://localhost:10636
#   scripts/test-slapd.sh stop
# Requires: apt-get install slapd ldap-utils
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASE="$ROOT/target/test-ldap"
DIR="$BASE/slapd"
CERTS="$BASE/certs"
LDAP_PORT="${SLAPD_LDAP_PORT:-10389}"
LDAPS_PORT="${SLAPD_LDAPS_PORT:-10636}"
SUFFIX="dc=example,dc=org"
ADMIN="cn=admin,$SUFFIX"
ADMIN_PW="admin"

stop() {
  if [[ -f "$DIR/slapd.pid" ]]; then
    kill "$(cat "$DIR/slapd.pid")" 2>/dev/null || true
    for _ in $(seq 50); do [[ -f "$DIR/slapd.pid" ]] || break; sleep 0.1; done
  fi
  rm -rf "$DIR"
}

start() {
  command -v slapd >/dev/null || PATH="$PATH:/usr/sbin"
  command -v slapd >/dev/null || { echo "slapd not installed (apt-get install slapd ldap-utils)"; exit 1; }
  stop
  "$ROOT/scripts/test-certs.sh" "$CERTS" >/dev/null
  mkdir -p "$DIR/slapd.d" "$DIR/data"
  cat > "$DIR/config.ldif" <<LDIF
dn: cn=config
objectClass: olcGlobal
cn: config
olcPidFile: $DIR/slapd.pid
olcTLSCACertificateFile: $CERTS/ca.pem
olcTLSCertificateFile: $CERTS/server.pem
olcTLSCertificateKeyFile: $CERTS/server.key

dn: cn=module{0},cn=config
objectClass: olcModuleList
cn: module{0}
olcModulePath: /usr/lib/ldap
olcModuleLoad: back_mdb
olcModuleLoad: memberof

dn: cn=schema,cn=config
objectClass: olcSchemaConfig
cn: schema

include: file:///etc/ldap/schema/core.ldif
include: file:///etc/ldap/schema/cosine.ldif
include: file:///etc/ldap/schema/inetorgperson.ldif
include: file:///etc/ldap/schema/nis.ldif

dn: olcDatabase={-1}frontend,cn=config
objectClass: olcDatabaseConfig
objectClass: olcFrontendConfig
olcDatabase: {-1}frontend
olcSizeLimit: size.soft=100 size.hard=100 size.prtotal=unlimited
olcAccess: {0}to dn.base="" by * read
olcAccess: {1}to dn.base="cn=Subschema" by * read

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config
olcAccess: {0}to * by * none

dn: olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
objectClass: olcMdbConfig
olcDatabase: {1}mdb
olcSuffix: $SUFFIX
olcRootDN: $ADMIN
olcRootPW: $ADMIN_PW
olcDbDirectory: $DIR/data
olcDbIndex: objectClass eq
olcDbIndex: uid,cn,mail eq,sub
olcDbIndex: member,uniqueMember,memberUid eq
olcAccess: {0}to attrs=userPassword by self write by anonymous auth by * none
olcAccess: {1}to * by * read

dn: olcOverlay={0}memberof,olcDatabase={1}mdb,cn=config
objectClass: olcOverlayConfig
objectClass: olcMemberOf
olcOverlay: {0}memberof
olcMemberOfRefInt: TRUE
olcMemberOfGroupOC: groupOfNames
olcMemberOfMemberAD: member
olcMemberOfMemberOfAD: memberOf
LDIF
  slapadd -n0 -F "$DIR/slapd.d" -l "$DIR/config.ldif" >/dev/null
  slapd -F "$DIR/slapd.d" -h "ldap://localhost:$LDAP_PORT/ ldaps://localhost:$LDAPS_PORT/"
  for _ in $(seq 50); do
    ldapsearch -x -H "ldap://localhost:$LDAP_PORT" -b "" -s base >/dev/null 2>&1 && break
    sleep 0.1
  done
  "$ROOT/scripts/seed-ldif.sh" | ldapadd -x -c -H "ldap://localhost:$LDAP_PORT" -D "$ADMIN" -w "$ADMIN_PW" >/dev/null
  echo "slapd running: ldap://localhost:$LDAP_PORT  ldaps://localhost:$LDAPS_PORT  ($ADMIN / $ADMIN_PW)"
}

case "${1:-start}" in
  start) start ;;
  stop) stop ;;
  *) echo "usage: $0 start|stop"; exit 2 ;;
esac
