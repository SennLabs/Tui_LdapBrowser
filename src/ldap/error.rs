//! Turns `ldap3` errors into messages a user can act on.

use std::fmt;

use ldap3::{LdapError, LdapResult};
use rustls::CertificateError;

use super::decode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    InvalidCredentials,
    StrongerAuthRequired,
    CertNameMismatch,
    CertUntrusted,
    CertExpired,
    Tls,
    Timeout,
    Refused,
    Dns,
    Disconnected,
    NoSuchObject,
    InsufficientAccess,
    BadFilter,
    UnavailableControl,
    Other,
}

#[derive(Debug, Clone)]
pub struct Failure {
    pub kind: ErrorKind,
    /// One-line plain-English summary.
    pub title: String,
    /// Suggested fix, if any.
    pub hint: Option<String>,
    /// Underlying error text (LDAP result code + diagnostic, or I/O error).
    pub detail: String,
    pub rc: Option<u32>,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.title)?;
        if let Some(h) = &self.hint {
            write!(f, " — {h}")?;
        }
        Ok(())
    }
}

impl Failure {
    pub fn new(kind: ErrorKind, title: impl Into<String>) -> Failure {
        Failure { kind, title: title.into(), hint: None, detail: String::new(), rc: None }
    }

    pub fn hint(mut self, h: impl Into<String>) -> Failure {
        self.hint = Some(h.into());
        self
    }

    pub fn detail(mut self, d: impl Into<String>) -> Failure {
        self.detail = d.into();
        self
    }

    pub fn other(msg: impl Into<String>) -> Failure {
        let m = msg.into();
        Failure::new(ErrorKind::Other, m.clone()).detail(m)
    }
}

/// Context needed to give specific advice.
pub struct Ctx<'a> {
    pub host: &'a str,
    pub ldaps: bool,
    pub port: u16,
}

pub fn from_result(r: &LdapResult) -> Failure {
    let detail = format!("result code {} ({}): {}", r.rc, rc_name(r.rc), r.text.trim());
    let f = match r.rc {
        49 => {
            let reason = decode::ad_bind_error(&r.text).unwrap_or("bad username or password");
            Failure::new(ErrorKind::InvalidCredentials, format!("Login failed: {reason}"))
        }
        8 | 13 => Failure::new(ErrorKind::StrongerAuthRequired, "The server refuses to accept a password over an unencrypted connection")
            .hint("switch this profile to \"scheme\": \"ldaps\" (port 636). Active Directory requires LDAPS for simple binds when LDAP signing is enforced"),
        32 => Failure::new(ErrorKind::NoSuchObject, "No such entry")
            .hint(if r.matched.is_empty() { "check the DN".to_string() } else { format!("closest existing parent: {}", r.matched) }),
        50 => Failure::new(ErrorKind::InsufficientAccess, "Access denied")
            .hint("the bound account lacks permission to read this"),
        12 => Failure::new(ErrorKind::UnavailableControl, "The server does not support a requested control"),
        87 => Failure::new(ErrorKind::BadFilter, "The server rejected the search filter"),
        1 if r.text.contains("000004DC") || r.text.to_ascii_lowercase().contains("successful bind must be completed") => {
            Failure::new(ErrorKind::InsufficientAccess, "The server requires a login before searching")
                .hint("set \"credentials\" for this profile; Active Directory does not allow anonymous searches")
        }
        _ => Failure::new(ErrorKind::Other, format!("LDAP error: {}", rc_name(r.rc))),
    };
    Failure { rc: Some(r.rc), detail, ..f }
}

pub fn classify(e: &LdapError, ctx: &Ctx) -> Failure {
    match e {
        LdapError::LdapResult { result } => from_result(result),
        LdapError::Timeout { .. } => Failure::new(ErrorKind::Timeout, "The server did not respond in time")
            .hint(if ctx.ldaps {
                "check host and port, and that the port speaks LDAPS (not plain LDAP)"
            } else {
                "check host and port, and that the port speaks plain LDAP (not LDAPS); raise timeout_secs for slow servers"
            })
            .detail(e.to_string()),
        LdapError::Rustls { source } => tls_failure(source, ctx).detail(e.to_string()),
        LdapError::DNSName { .. } => Failure::new(ErrorKind::Tls, format!("\"{}\" is not a valid TLS server name", ctx.host)).detail(e.to_string()),
        LdapError::Io { source } => {
            if let Some(tls) = source.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>()) {
                return tls_failure(tls, ctx).detail(e.to_string());
            }
            use std::io::ErrorKind as K;
            let msg = source.to_string();
            let f = match source.kind() {
                K::ConnectionRefused => Failure::new(ErrorKind::Refused, format!("Connection refused by {}:{}", ctx.host, ctx.port))
                    .hint("is the LDAP service listening on this port?"),
                K::ConnectionReset | K::BrokenPipe | K::UnexpectedEof | K::ConnectionAborted => {
                    Failure::new(ErrorKind::Disconnected, "The connection was closed by the server").hint(if ctx.ldaps {
                        "if this happens on connect, the port may be plain LDAP rather than LDAPS"
                    } else {
                        "if this happens on connect, the port may be LDAPS; try \"scheme\": \"ldaps\""
                    })
                }
                K::TimedOut => Failure::new(ErrorKind::Timeout, "Connection timed out"),
                _ if msg.contains("lookup") || msg.contains("Name or service not known") || msg.contains("resolve") => {
                    Failure::new(ErrorKind::Dns, format!("Cannot resolve host name \"{}\"", ctx.host))
                }
                _ if msg.contains("corrupt message") || msg.contains("InvalidContentType") => {
                    Failure::new(ErrorKind::Tls, "TLS handshake failed: the server did not speak TLS")
                        .hint("this port is probably plain LDAP; use \"scheme\": \"ldap\" or the LDAPS port (636)")
                }
                _ => Failure::new(ErrorKind::Other, format!("Network error: {msg}")),
            };
            f.detail(e.to_string())
        }
        LdapError::OpSend { .. } | LdapError::ResultRecv { .. } | LdapError::EndOfStream => {
            Failure::new(ErrorKind::Disconnected, "Not connected to the server")
                .hint("press R to reconnect")
                .detail(e.to_string())
        }
        LdapError::FilterParsing => Failure::new(ErrorKind::BadFilter, "Invalid search filter").detail(e.to_string()),
        _ => Failure::other(e.to_string()),
    }
}

fn tls_failure(e: &rustls::Error, ctx: &Ctx) -> Failure {
    match e {
        rustls::Error::InvalidCertificate(ce) => match ce {
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
                let presented = match ce {
                    CertificateError::NotValidForNameContext { presented, .. } if !presented.is_empty() => presented
                        .iter()
                        .map(|n| {
                            n.strip_prefix("DnsName(\"")
                                .or_else(|| n.strip_prefix("IpAddress("))
                                .map(|x| x.trim_end_matches(')').trim_end_matches('"').to_string())
                                .unwrap_or_else(|| n.clone())
                        })
                        .collect::<Vec<_>>()
                        .join(", "),
                    _ => "a different name".into(),
                };
                Failure::new(
                    ErrorKind::CertNameMismatch,
                    format!("Certificate name mismatch: the certificate is for {presented}, but you connected to \"{}\"", ctx.host),
                )
                .hint("set \"host\" to a name listed in the certificate (usually the server's FQDN, not an IP address or short name)")
            }
            CertificateError::UnknownIssuer | CertificateError::BadSignature => Failure::new(
                ErrorKind::CertUntrusted,
                "The server's certificate is not signed by a trusted CA",
            )
            .hint(
                "set \"ca_cert\" to your CA's PEM file (preferred), or \"insecure_skip_verify\": true to skip checking",
            ),
            CertificateError::Expired | CertificateError::ExpiredContext { .. } => {
                Failure::new(ErrorKind::CertExpired, "The server's certificate has expired")
                    .hint("renew the certificate, or set \"insecure_skip_verify\": true as a temporary workaround")
            }
            CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => {
                Failure::new(ErrorKind::CertExpired, "The server's certificate is not valid yet")
                    .hint("check the clock on this machine and on the server")
            }
            other => Failure::new(ErrorKind::Tls, format!("Certificate rejected: {other:?}"))
                .hint("set \"ca_cert\" or \"insecure_skip_verify\" if the certificate is self-signed"),
        },
        rustls::Error::InvalidMessage(_) => {
            Failure::new(ErrorKind::Tls, "TLS handshake failed: the server did not speak TLS")
                .hint("this port is probably plain LDAP; use \"scheme\": \"ldap\" or the LDAPS port (636)")
        }
        other => Failure::new(ErrorKind::Tls, format!("TLS error: {other}")),
    }
}

pub fn rc_name(rc: u32) -> &'static str {
    match rc {
        0 => "success",
        1 => "operationsError",
        2 => "protocolError",
        3 => "timeLimitExceeded",
        4 => "sizeLimitExceeded",
        7 => "authMethodNotSupported",
        8 => "strongerAuthRequired",
        10 => "referral",
        11 => "adminLimitExceeded",
        12 => "unavailableCriticalExtension",
        13 => "confidentialityRequired",
        16 => "noSuchAttribute",
        17 => "undefinedAttributeType",
        18 => "inappropriateMatching",
        32 => "noSuchObject",
        34 => "invalidDNSyntax",
        48 => "inappropriateAuthentication",
        49 => "invalidCredentials",
        50 => "insufficientAccessRights",
        51 => "busy",
        52 => "unavailable",
        53 => "unwillingToPerform",
        80 => "other",
        87 => "filterError",
        88 => "abandoned",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn res(rc: u32, text: &str) -> LdapResult {
        LdapResult { rc, matched: String::new(), text: text.into(), refs: vec![], ctrls: vec![] }
    }

    #[test]
    fn ad_bad_password() {
        let f = from_result(&res(
            49,
            "80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 775, v4563",
        ));
        assert_eq!(f.kind, ErrorKind::InvalidCredentials);
        assert!(f.title.contains("account locked out"));
        assert!(f.detail.contains("invalidCredentials"));
    }

    #[test]
    fn stronger_auth() {
        let f = from_result(&res(
            8,
            "00002028: LdapErr: DSID-0C090259, comment: The server requires binds to turn on integrity checking",
        ));
        assert_eq!(f.kind, ErrorKind::StrongerAuthRequired);
        assert!(f.hint.unwrap().contains("ldaps"));
    }

    #[test]
    fn ad_anonymous_search() {
        let f = from_result(&res(
            1,
            "000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4563",
        ));
        assert_eq!(f.kind, ErrorKind::InsufficientAccess);
    }

    #[test]
    fn name_mismatch() {
        let ctx = Ctx { host: "10.0.0.5", ldaps: true, port: 636 };
        let e = rustls::Error::InvalidCertificate(CertificateError::NotValidForNameContext {
            expected: rustls::pki_types::ServerName::try_from("10.0.0.5").unwrap().to_owned(),
            presented: vec!["DnsName(\"dc01.example.local\")".into()],
        });
        let f = tls_failure(&e, &ctx);
        assert_eq!(f.kind, ErrorKind::CertNameMismatch);
        assert!(f.title.contains("dc01.example.local"));
        assert!(f.title.contains("10.0.0.5"));
    }

    #[test]
    fn untrusted() {
        let ctx = Ctx { host: "h", ldaps: true, port: 636 };
        let f = tls_failure(&rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer), &ctx);
        assert_eq!(f.kind, ErrorKind::CertUntrusted);
        assert!(f.hint.unwrap().contains("ca_cert"));
    }
}
