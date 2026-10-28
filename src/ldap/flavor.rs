//! Server flavor detection from the RootDSE, and per-flavor defaults.

use std::collections::HashMap;

use crate::config::{FlavorSetting, Profile};

use super::filter;

pub const PAGED_RESULTS_OID: &str = "1.2.840.113556.1.4.319";
pub const IN_CHAIN_OID: &str = "1.2.840.113556.1.4.1941";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    Ad,
    OpenLdap,
    Lldap,
    Generic,
}

impl Flavor {
    pub fn label(self) -> &'static str {
        match self {
            Flavor::Ad => "AD",
            Flavor::OpenLdap => "OpenLDAP",
            Flavor::Lldap => "LLDAP",
            Flavor::Generic => "LDAP",
        }
    }

    pub fn user_filter(self) -> &'static str {
        match self {
            Flavor::Ad => {
                "(&(objectCategory=person)(objectClass=user)(|(sAMAccountName=*{q}*)(cn=*{q}*)(displayName=*{q}*)(mail=*{q}*)(userPrincipalName=*{q}*)))"
            }
            Flavor::OpenLdap | Flavor::Generic => {
                "(&(|(objectClass=inetOrgPerson)(objectClass=posixAccount))(|(uid=*{q}*)(cn=*{q}*)(mail=*{q}*)))"
            }
            Flavor::Lldap => "(&(objectClass=person)(|(uid=*{q}*)(cn=*{q}*)(mail=*{q}*)))",
        }
    }

    pub fn group_filter(self) -> &'static str {
        match self {
            Flavor::Ad => "(&(objectClass=group)(|(cn=*{q}*)(sAMAccountName=*{q}*)))",
            Flavor::OpenLdap | Flavor::Generic => {
                "(&(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))(cn=*{q}*))"
            }
            Flavor::Lldap => "(&(objectClass=groupOfUniqueNames)(cn=*{q}*))",
        }
    }

    /// Filter for the children of a tree node whose RDN value starts with `prefix`.
    pub fn child_prefix_filter(self, prefix: &str) -> String {
        let p = filter::escape(prefix);
        match self {
            Flavor::Ad => format!("(name={p}*)"),
            _ => format!("(|(cn={p}*)(ou={p}*)(uid={p}*)(dc={p}*)(o={p}*))"),
        }
    }

    pub fn supports_nested_groups(self) -> bool {
        !matches!(self, Flavor::Lldap)
    }
}

/// DN-syntax attributes that can be followed.
pub fn is_dn_attribute(name: &str) -> bool {
    const DN_ATTRS: &[&str] = &[
        "member",
        "memberof",
        "uniquemember",
        "manager",
        "directreports",
        "seealso",
        "owner",
        "secretary",
        "managedby",
        "managedobjects",
        "distinguishedname",
        "entrydn",
        "creatorsname",
        "modifiersname",
        "subschemasubentry",
        "objectcategory",
        "defaultobjectcategory",
        "msds-membertransitive",
        "msds-memberoftransitive",
        "roleoccupant",
        "serverreference",
        "serverreferencebl",
        "frscomputerreference",
        "msdfsr-computerreference",
        "msds-isdomainfor",
        "msds-hasmasterncs",
        "hasmasterncs",
        "dmdlocation",
        "fsmoroleowner",
        "rIDSetReferences",
        "rIDManagerReference",
        "namingcontexts",
        "defaultnamingcontext",
        "configurationnamingcontext",
        "schemanamingcontext",
        "rootdomainnamingcontext",
        "dsservicename",
        "altrecipient",
        "publicdelegates",
        "publicdelegatesbl",
        "homemdb",
        "msexchhomeservername",
        "wellknownobjects",
        "otherwellknownobjects",
        "lastknownparent",
        "queryPolicyObject",
    ];
    let n = name.split(";range=").next().unwrap_or(name);
    DN_ATTRS.iter().any(|a| a.eq_ignore_ascii_case(n))
}

#[derive(Debug, Clone, Default)]
pub struct RootDse {
    pub attrs: HashMap<String, Vec<String>>,
}

impl RootDse {
    pub fn get(&self, name: &str) -> Vec<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    pub fn first(&self, name: &str) -> Option<&str> {
        self.get(name).into_iter().next()
    }

    pub fn has(&self, name: &str) -> bool {
        !self.get(name).is_empty()
    }

    pub fn naming_contexts(&self) -> Vec<String> {
        self.get("namingContexts").into_iter().map(str::to_string).collect()
    }

    pub fn supports_control(&self, oid: &str) -> bool {
        self.get("supportedControl").contains(&oid)
    }

    pub fn detect(&self) -> Flavor {
        // Vendor first: LLDAP's RootDSE also carries `isGlobalCatalogReady: false`.
        let vendor = self.get("vendorName").join(" ").to_ascii_lowercase();
        if vendor.contains("lldap") {
            return Flavor::Lldap;
        }
        if self.has("forestFunctionality")
            || self.has("domainFunctionality")
            || self.get("isGlobalCatalogReady").iter().any(|v| v.eq_ignore_ascii_case("TRUE"))
        {
            return Flavor::Ad;
        }
        if self.get("objectClass").iter().any(|c| c.eq_ignore_ascii_case("OpenLDAProotDSE")) {
            return Flavor::OpenLdap;
        }
        Flavor::Generic
    }

    /// The base DN to browse when none is configured.
    pub fn default_base(&self) -> Option<String> {
        self.first("defaultNamingContext").map(str::to_string).or_else(|| self.naming_contexts().into_iter().next())
    }
}

pub fn resolve_flavor(setting: FlavorSetting, rootdse: &RootDse) -> Flavor {
    match setting {
        FlavorSetting::Ad => Flavor::Ad,
        FlavorSetting::OpenLdap => Flavor::OpenLdap,
        FlavorSetting::Lldap => Flavor::Lldap,
        FlavorSetting::Auto => rootdse.detect(),
    }
}

pub fn user_filter(profile: &Profile, flavor: Flavor, q: &str) -> String {
    let t = profile.search.user_filter.as_deref().unwrap_or(flavor.user_filter());
    filter::from_template(t, q)
}

pub fn group_filter(profile: &Profile, flavor: Flavor, q: &str) -> String {
    let t = profile.search.group_filter.as_deref().unwrap_or(flavor.group_filter());
    filter::from_template(t, q)
}

#[cfg(test)]
pub mod fixtures {
    use super::RootDse;

    fn dse(pairs: &[(&str, &[&str])]) -> RootDse {
        RootDse {
            attrs: pairs.iter().map(|(k, v)| (k.to_string(), v.iter().map(|s| s.to_string()).collect())).collect(),
        }
    }

    /// Trimmed from a Windows Server 2019 DC.
    pub fn ad() -> RootDse {
        dse(&[
            ("defaultNamingContext", &["DC=example,DC=local"]),
            (
                "namingContexts",
                &[
                    "DC=example,DC=local",
                    "CN=Configuration,DC=example,DC=local",
                    "CN=Schema,CN=Configuration,DC=example,DC=local",
                    "DC=DomainDnsZones,DC=example,DC=local",
                    "DC=ForestDnsZones,DC=example,DC=local",
                ],
            ),
            ("forestFunctionality", &["7"]),
            ("domainFunctionality", &["7"]),
            ("isGlobalCatalogReady", &["TRUE"]),
            ("supportedControl", &["1.2.840.113556.1.4.319", "1.2.840.113556.1.4.801"]),
        ])
    }

    pub fn openldap() -> RootDse {
        dse(&[
            ("objectClass", &["top", "OpenLDAProotDSE"]),
            ("namingContexts", &["dc=example,dc=org"]),
            ("supportedControl", &["1.2.840.113556.1.4.319", "2.16.840.1.113730.3.4.18"]),
        ])
    }

    /// Verbatim from LLDAP v0.6.3. Note `isGlobalCatalogReady: false` and no supportedControl.
    pub fn lldap() -> RootDse {
        dse(&[
            ("objectClass", &["top"]),
            ("vendorName", &["LLDAP"]),
            ("vendorVersion", &["lldap_0.1.1"]),
            ("supportedLDAPVersion", &["3"]),
            ("supportedExtension", &["1.3.6.1.4.1.4203.1.11.1", "1.3.6.1.4.1.4203.1.11.3"]),
            ("supportedFeatures", &["1.3.6.1.4.1.4203.1.5.1"]),
            ("defaultNamingContext", &["dc=example,dc=com"]),
            ("namingContexts", &["dc=example,dc=com"]),
            ("isGlobalCatalogReady", &["false"]),
            ("subschemaSubentry", &["cn=Subschema"]),
        ])
    }

    pub fn generic() -> RootDse {
        dse(&[("namingContexts", &["o=corp"])])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn detection() {
        assert_eq!(fixtures::ad().detect(), Flavor::Ad);
        assert_eq!(fixtures::openldap().detect(), Flavor::OpenLdap);
        assert_eq!(fixtures::lldap().detect(), Flavor::Lldap);
        assert_eq!(fixtures::generic().detect(), Flavor::Generic);
    }

    #[test]
    fn explicit_setting_wins() {
        assert_eq!(resolve_flavor(FlavorSetting::Lldap, &fixtures::ad()), Flavor::Lldap);
        assert_eq!(resolve_flavor(FlavorSetting::Auto, &fixtures::ad()), Flavor::Ad);
    }

    #[test]
    fn default_base() {
        assert_eq!(fixtures::ad().default_base().unwrap(), "DC=example,DC=local");
        assert_eq!(fixtures::openldap().default_base().unwrap(), "dc=example,dc=org");
    }

    #[test]
    fn paging_support() {
        assert!(fixtures::ad().supports_control(PAGED_RESULTS_OID));
        assert!(!fixtures::lldap().supports_control(PAGED_RESULTS_OID));
    }

    #[test]
    fn all_default_filters_parse() {
        for f in [Flavor::Ad, Flavor::OpenLdap, Flavor::Lldap, Flavor::Generic] {
            for t in [f.user_filter(), f.group_filter()] {
                filter::validate(&filter::from_template(t, "jo(e")).unwrap();
            }
            filter::validate(&f.child_prefix_filter("a*")).unwrap();
        }
    }

    #[test]
    fn overrides_apply() {
        let cfg =
            Config::parse(r#"{"profiles":{"p":{"host":"h","search":{"user_filter":"(uid={q})"}}}}"#, None).unwrap();
        let p = cfg.profile("p").unwrap();
        assert_eq!(user_filter(p, Flavor::Ad, "bob"), "(uid=bob)");
        assert!(group_filter(p, Flavor::Ad, "x").contains("objectClass=group"));
    }

    #[test]
    fn ad_filter_excludes_computers_via_category() {
        assert!(Flavor::Ad.user_filter().contains("objectCategory=person"));
    }

    #[test]
    fn dn_attributes() {
        assert!(is_dn_attribute("memberOf"));
        assert!(is_dn_attribute("member;range=0-1499"));
        assert!(!is_dn_attribute("cn"));
    }
}
