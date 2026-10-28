//! Human-readable decoding of attribute values (mostly Active Directory formats).

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};

use super::model::Value;

/// Formats an AD `objectGUID` (mixed-endian) as the usual `{xxxxxxxx-xxxx-...}` string.
pub fn guid_to_string(b: &[u8]) -> Option<String> {
    if b.len() != 16 {
        return None;
    }
    Some(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    ))
}

/// Formats a binary SID as `S-1-5-21-...`.
pub fn sid_to_string(b: &[u8]) -> Option<String> {
    if b.len() < 8 {
        return None;
    }
    let rev = b[0];
    let count = b[1] as usize;
    if b.len() != 8 + 4 * count {
        return None;
    }
    let auth = b[2..8].iter().fold(0u64, |acc, x| (acc << 8) | *x as u64);
    let mut s = format!("S-{rev}-{auth}");
    for i in 0..count {
        let o = 8 + 4 * i;
        let sub = u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        s.push_str(&format!("-{sub}"));
    }
    Some(s)
}

/// Parses `S-1-5-21-...` into binary form.
pub fn sid_from_string(s: &str) -> Option<Vec<u8>> {
    let mut parts = s.strip_prefix("S-")?.split('-');
    let rev: u8 = parts.next()?.parse().ok()?;
    let auth: u64 = parts.next()?.parse().ok()?;
    let subs: Vec<u32> = parts.map(|p| p.parse().ok()).collect::<Option<_>>()?;
    let mut out = vec![rev, subs.len() as u8];
    out.extend_from_slice(&auth.to_be_bytes()[2..]);
    for sub in subs {
        out.extend_from_slice(&sub.to_le_bytes());
    }
    Some(out)
}

/// Builds the SID of a user's primary group: the domain part of `user_sid` plus `rid`.
pub fn primary_group_sid(user_sid: &[u8], rid: u32) -> Option<Vec<u8>> {
    let s = sid_to_string(user_sid)?;
    let (domain, _) = s.rsplit_once('-')?;
    sid_from_string(&format!("{domain}-{rid}"))
}

/// Escapes raw bytes for use as a filter assertion value (`\xx` per byte).
pub fn filter_escape_bytes(b: &[u8]) -> String {
    b.iter().map(|x| format!("\\{x:02x}")).collect()
}

/// AD FILETIME (100ns intervals since 1601-01-01 UTC). 0 and i64::MAX mean "never".
pub fn filetime(v: i64) -> String {
    if v == 0 || v == i64::MAX {
        return "never".into();
    }
    const EPOCH_DIFF_SECS: i64 = 11_644_473_600;
    let secs = v / 10_000_000 - EPOCH_DIFF_SECS;
    match Utc.timestamp_opt(secs, 0).single() {
        Some(t) => t.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => "invalid".into(),
    }
}

/// LDAP GeneralizedTime, e.g. `20240311083000.0Z` or `20240311083000Z`.
pub fn generalized_time(s: &str) -> Option<String> {
    let s = s.trim();
    let core = s.trim_end_matches('Z');
    let core = core.split(['.', ',']).next()?;
    if core.len() != 14 || !core.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let ndt = NaiveDateTime::parse_from_str(core, "%Y%m%d%H%M%S").ok()?;
    let dt: DateTime<Utc> = Utc.from_utc_datetime(&ndt);
    Some(dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
}

const UAC_FLAGS: &[(u32, &str)] = &[
    (0x0001, "SCRIPT"),
    (0x0002, "ACCOUNTDISABLE"),
    (0x0008, "HOMEDIR_REQUIRED"),
    (0x0010, "LOCKOUT"),
    (0x0020, "PASSWD_NOTREQD"),
    (0x0040, "PASSWD_CANT_CHANGE"),
    (0x0080, "ENCRYPTED_TEXT_PWD_ALLOWED"),
    (0x0100, "TEMP_DUPLICATE_ACCOUNT"),
    (0x0200, "NORMAL_ACCOUNT"),
    (0x0800, "INTERDOMAIN_TRUST_ACCOUNT"),
    (0x1000, "WORKSTATION_TRUST_ACCOUNT"),
    (0x2000, "SERVER_TRUST_ACCOUNT"),
    (0x10000, "DONT_EXPIRE_PASSWORD"),
    (0x20000, "MNS_LOGON_ACCOUNT"),
    (0x40000, "SMARTCARD_REQUIRED"),
    (0x80000, "TRUSTED_FOR_DELEGATION"),
    (0x100000, "NOT_DELEGATED"),
    (0x200000, "USE_DES_KEY_ONLY"),
    (0x400000, "DONT_REQ_PREAUTH"),
    (0x800000, "PASSWORD_EXPIRED"),
    (0x1000000, "TRUSTED_TO_AUTH_FOR_DELEGATION"),
    (0x4000000, "PARTIAL_SECRETS_ACCOUNT"),
];

pub fn uac_flags(v: u32) -> String {
    let names: Vec<&str> = UAC_FLAGS.iter().filter(|(b, _)| v & b != 0).map(|(_, n)| *n).collect();
    if names.is_empty() { "none".into() } else { names.join(" | ") }
}

pub fn group_type(v: i64) -> String {
    let v = v as i32 as u32;
    let kind = if v & 0x8000_0000 != 0 { "Security" } else { "Distribution" };
    let scope = if v & 0x1 != 0 {
        "Builtin local"
    } else if v & 0x2 != 0 {
        "Global"
    } else if v & 0x4 != 0 {
        "Domain local"
    } else if v & 0x8 != 0 {
        "Universal"
    } else {
        "Unknown scope"
    };
    format!("{kind}, {scope}")
}

const SAM_ACCOUNT_TYPES: &[(u32, &str)] = &[
    (0x0, "DOMAIN_OBJECT"),
    (0x10000000, "GROUP_OBJECT"),
    (0x10000001, "NON_SECURITY_GROUP_OBJECT"),
    (0x20000000, "ALIAS_OBJECT"),
    (0x20000001, "NON_SECURITY_ALIAS_OBJECT"),
    (0x30000000, "USER_OBJECT"),
    (0x30000001, "MACHINE_ACCOUNT"),
    (0x30000002, "TRUST_ACCOUNT"),
];

/// Interprets the `data XXX` sub-code in an AD invalidCredentials (49) diagnostic message.
pub fn ad_bind_error(text: &str) -> Option<&'static str> {
    let lower = text.to_ascii_lowercase();
    let code = lower.split("data ").nth(1)?.split([',', ' ']).next()?;
    Some(match code {
        "525" => "user not found",
        "52e" => "bad username or password",
        "530" => "logon not permitted at this time",
        "531" => "logon not permitted from this workstation",
        "532" => "password expired",
        "533" => "account disabled",
        "568" => "too many security IDs in token",
        "701" => "account expired",
        "773" => "user must change password before first logon",
        "775" => "account locked out",
        _ => return None,
    })
}

const FILETIME_ATTRS: &[&str] = &[
    "pwdlastset",
    "lastlogon",
    "lastlogontimestamp",
    "lastlogoff",
    "accountexpires",
    "badpasswordtime",
    "lockouttime",
    "msds-userpasswordexpirytimecomputed",
    "msds-lastsuccessfulinteractivelogontime",
    "msds-lastfailedinteractivelogontime",
    "creationtime",
];

const GENERALIZED_TIME_ATTRS: &[&str] = &[
    "whencreated",
    "whenchanged",
    "createtimestamp",
    "modifytimestamp",
    "pwdchangedtime",
    "pwdaccountlockedtime",
    "dscorepropagationdata",
];

pub fn is_filetime_attr(attr: &str) -> bool {
    FILETIME_ATTRS.contains(&attr.to_ascii_lowercase().as_str())
}

pub fn is_generalized_time_attr(attr: &str) -> bool {
    GENERALIZED_TIME_ATTRS.contains(&attr.to_ascii_lowercase().as_str())
}

/// A readable annotation for a value, shown next to the raw form. `None` if nothing to add.
pub fn annotate(attr: &str, v: &Value) -> Option<String> {
    let a = attr.to_ascii_lowercase();
    let a = a.split(";range=").next().unwrap_or(&a);
    match v {
        Value::Binary(b) => match a {
            "objectguid" | "schemaidguid" | "msexchmailboxguid" | "ms-ds-consistencyguid" => guid_to_string(b),
            "objectsid" | "tokengroups" | "sidhistory" | "securityidentifier" => sid_to_string(b),
            _ => None,
        },
        Value::Text(s) => {
            if FILETIME_ATTRS.contains(&a) {
                return s.parse::<i64>().ok().map(filetime);
            }
            if GENERALIZED_TIME_ATTRS.contains(&a) {
                return generalized_time(s);
            }
            match a {
                "useraccountcontrol" | "msds-user-account-control-computed" => s.parse::<u32>().ok().map(uac_flags),
                "grouptype" => s.parse::<i64>().ok().map(group_type),
                "samaccounttype" => s
                    .parse::<u32>()
                    .ok()
                    .and_then(|n| SAM_ACCOUNT_TYPES.iter().find(|(v, _)| *v == n).map(|(_, s)| s.to_string())),
                "primarygroupid" => s.parse::<u32>().ok().and_then(|rid| match rid {
                    513 => Some("Domain Users".into()),
                    514 => Some("Domain Guests".into()),
                    515 => Some("Domain Computers".into()),
                    516 => Some("Domain Controllers".into()),
                    521 => Some("Read-only Domain Controllers".into()),
                    _ => None,
                }),
                _ => None,
            }
        }
    }
}

/// Password-like attributes are masked in the entry table (still viewable with `v`).
pub fn is_secret_attr(attr: &str) -> bool {
    const SECRET: &[&str] = &["userpassword", "unicodepwd", "sambantpassword", "sambalmpassword", "authpassword"];
    SECRET.iter().any(|s| s.eq_ignore_ascii_case(attr))
}

/// One-line display of a value: text as-is, binary as decoded form or hex.
pub fn display_value(attr: &str, v: &Value) -> String {
    if is_secret_attr(attr) {
        return "•••••••• (hidden — v to view)".into();
    }
    match v {
        Value::Text(s) => s.replace(['\n', '\r'], "⏎"),
        Value::Binary(b) => annotate(attr, v).unwrap_or_else(|| {
            let hex: String = b.iter().take(32).map(|x| format!("{x:02x}")).collect();
            if b.len() > 32 { format!("<{} bytes> {hex}…", b.len()) } else { format!("<{} bytes> {hex}", b.len()) }
        }),
    }
}

/// Classic 16-bytes-per-line hex dump.
pub fn hexdump(b: &[u8]) -> Vec<String> {
    b.chunks(16)
        .enumerate()
        .map(|(i, chunk)| {
            let hex: Vec<String> = chunk.iter().map(|x| format!("{x:02x}")).collect();
            let ascii: String =
                chunk.iter().map(|&x| if x.is_ascii_graphic() || x == b' ' { x as char } else { '.' }).collect();
            format!("{:08x}  {:<48} {}", i * 16, hex.join(" "), ascii)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid() {
        let b = [0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(guid_to_string(&b).unwrap(), "12345678-9abc-def0-0102-030405060708");
        assert!(guid_to_string(&b[..15]).is_none());
    }

    #[test]
    fn sid_roundtrip() {
        let s = "S-1-5-21-3623811015-3361044348-30300820-1013";
        let b = sid_from_string(s).unwrap();
        assert_eq!(b.len(), 8 + 4 * 5);
        assert_eq!(sid_to_string(&b).unwrap(), s);
        assert_eq!(sid_to_string(&sid_from_string("S-1-5-32-544").unwrap()).unwrap(), "S-1-5-32-544");
    }

    #[test]
    fn primary_group() {
        let user = sid_from_string("S-1-5-21-1-2-3-1105").unwrap();
        let g = primary_group_sid(&user, 513).unwrap();
        assert_eq!(sid_to_string(&g).unwrap(), "S-1-5-21-1-2-3-513");
        assert!(filter_escape_bytes(&g).starts_with("\\01\\05\\00"));
    }

    #[test]
    fn filetimes() {
        assert_eq!(filetime(0), "never");
        assert_eq!(filetime(i64::MAX), "never");
        // 2024-02-12 06:52:25 UTC
        assert_eq!(filetime(133_521_943_450_000_000), "2024-02-12 06:52:25 UTC");
    }

    #[test]
    fn gentime() {
        assert_eq!(generalized_time("20240311083000.0Z").unwrap(), "2024-03-11 08:30:00 UTC");
        assert_eq!(generalized_time("20240311083000Z").unwrap(), "2024-03-11 08:30:00 UTC");
        assert!(generalized_time("garbage").is_none());
    }

    #[test]
    fn uac() {
        assert_eq!(uac_flags(512), "NORMAL_ACCOUNT");
        assert_eq!(uac_flags(514), "ACCOUNTDISABLE | NORMAL_ACCOUNT");
        assert_eq!(uac_flags(66048), "NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD");
    }

    #[test]
    fn group_types() {
        assert_eq!(group_type(-2147483646), "Security, Global");
        assert_eq!(group_type(-2147483644), "Security, Domain local");
        assert_eq!(group_type(8), "Distribution, Universal");
    }

    #[test]
    fn bind_errors() {
        let t = "80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 52e, v4563";
        assert_eq!(ad_bind_error(t), Some("bad username or password"));
        assert_eq!(ad_bind_error(&t.replace("52e", "775")), Some("account locked out"));
        assert_eq!(ad_bind_error("something else"), None);
    }

    #[test]
    fn annotations() {
        assert_eq!(
            annotate("userAccountControl", &Value::Text("514".into())).unwrap(),
            "ACCOUNTDISABLE | NORMAL_ACCOUNT"
        );
        assert_eq!(annotate("pwdLastSet", &Value::Text("0".into())).unwrap(), "never");
        assert_eq!(annotate("primaryGroupID", &Value::Text("513".into())).unwrap(), "Domain Users");
        assert!(annotate("cn", &Value::Text("x".into())).is_none());
        let sid = sid_from_string("S-1-5-32-544").unwrap();
        assert_eq!(annotate("objectSid", &Value::Binary(sid)).unwrap(), "S-1-5-32-544");
    }

    #[test]
    fn hexdump_format() {
        let lines = hexdump(b"Hello, world! 0123456789");
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("00000000  48 65 6c 6c"));
        assert!(lines[0].ends_with("Hello, world! 01"));
    }
}
