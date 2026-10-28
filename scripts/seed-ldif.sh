#!/usr/bin/env bash
# Prints the LDIF used to seed the OpenLDAP test server.
set -euo pipefail
S="dc=example,dc=org"
cat <<LDIF
dn: $S
objectClass: dcObject
objectClass: organization
dc: example
o: Example Org

dn: ou=people,$S
objectClass: organizationalUnit
ou: people

dn: ou=groups,$S
objectClass: organizationalUnit
ou: groups

dn: ou=bulk,$S
objectClass: organizationalUnit
ou: bulk
description: 250 users, more than the server's unpaged size limit of 100

dn: ou=empty,$S
objectClass: organizationalUnit
ou: empty

LDIF
for u in alice bob carol; do
  U="$(tr '[:lower:]' '[:upper:]' <<< "${u:0:1}")${u:1}"
  cat <<LDIF
dn: uid=$u,ou=people,$S
objectClass: inetOrgPerson
objectClass: posixAccount
uid: $u
cn: $U Example
sn: Example
givenName: $U
displayName: $U Example
mail: $u@example.org
uidNumber: $((1000 + ${#u}))
gidNumber: 1000
homeDirectory: /home/$u
userPassword: ${u}pw

LDIF
done
cat <<LDIF
dn: cn=Doe\, Jane,ou=people,$S
objectClass: inetOrgPerson
cn: Doe, Jane
sn: Doe
mail: jane.doe@example.org
manager: uid=alice,ou=people,$S
description: Has a comma in her RDN

dn: cn=staff,ou=groups,$S
objectClass: groupOfNames
cn: staff
member: uid=alice,ou=people,$S
member: uid=bob,ou=people,$S

dn: cn=admins,ou=groups,$S
objectClass: groupOfNames
cn: admins
member: uid=alice,ou=people,$S

dn: cn=everyone,ou=groups,$S
objectClass: groupOfNames
cn: everyone
description: Contains the staff group (nesting)
member: cn=staff,ou=groups,$S
member: uid=carol,ou=people,$S

dn: cn=cycle-a,ou=groups,$S
objectClass: groupOfNames
cn: cycle-a
member: cn=everyone,ou=groups,$S

dn: cn=cycle-b,ou=groups,$S
objectClass: groupOfNames
cn: cycle-b
member: cn=cycle-a,ou=groups,$S

dn: cn=cycle-a,ou=groups,$S
changetype: modify
add: member
member: cn=cycle-b,ou=groups,$S

dn: cn=posix-devs,ou=groups,$S
objectClass: posixGroup
cn: posix-devs
gidNumber: 2000
memberUid: bob
memberUid: carol
memberUid: ghost

LDIF
for i in $(seq -w 0 249); do
  cat <<LDIF
dn: uid=user$i,ou=bulk,$S
objectClass: inetOrgPerson
uid: user$i
cn: User $i
sn: $i

LDIF
done
