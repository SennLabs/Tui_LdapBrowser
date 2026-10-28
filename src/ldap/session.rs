//! A connected, bound LDAP session and all read-only operations the UI needs.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use futures::StreamExt;
use ldap3::adapters::{Adapter, PagedResults};
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, ResultEntry, Scope, SearchEntry, SearchOptions};
use secrecy::{ExposeSecret, SecretString};
use tracing::{debug, info, warn};

use crate::config::{Profile, Scheme};

use super::decode;
use super::error::{self, Ctx, ErrorKind, Failure};
use super::filter;
use super::flavor::{self, Flavor, IN_CHAIN_OID, PAGED_RESULTS_OID, RootDse};
use super::model::{self, Child, ChildList, Entry, EntryKind, Hit, HitList};
use super::range;

pub type Result<T> = std::result::Result<T, Failure>;

#[derive(Clone)]
pub enum Creds {
    Anonymous,
    Simple { bind_dn: String, password: SecretString },
}

impl std::fmt::Debug for Creds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Creds::Anonymous => write!(f, "Anonymous"),
            Creds::Simple { bind_dn, .. } => write!(f, "Simple {{ bind_dn: {bind_dn:?}, password: [REDACTED] }}"),
        }
    }
}

/// Summary of a connection, for display.
#[derive(Debug, Clone)]
pub struct ConnInfo {
    pub flavor: Flavor,
    pub base_dn: String,
    pub naming_contexts: Vec<String>,
    pub bound_as: Option<String>,
    pub vendor: Option<String>,
    pub paging: bool,
}

/// Holds the message id of the in-flight operation so it can be abandoned.
pub type MsgSlot = Arc<AtomicI32>;

const SUMMARY_ATTRS: &[&str] =
    &["objectClass", "cn", "displayName", "name", "uid", "sAMAccountName", "mail", "description", "ou"];

const ROOTDSE_ATTRS: &[&str] = &[
    "*",
    "+",
    "namingContexts",
    "defaultNamingContext",
    "configurationNamingContext",
    "schemaNamingContext",
    "rootDomainNamingContext",
    "supportedControl",
    "supportedExtension",
    "supportedLDAPVersion",
    "vendorName",
    "vendorVersion",
    "objectClass",
    "forestFunctionality",
    "domainFunctionality",
    "isGlobalCatalogReady",
    "dnsHostName",
    "subschemaSubentry",
];

const RESOLVE_CAP: usize = 1000;
const NESTED_DEPTH_LIMIT: usize = 10;

pub struct Session {
    ldap: Ldap,
    pub profile: Profile,
    pub rootdse: RootDse,
    pub flavor: Flavor,
    pub base_dn: String,
    pub bound_as: Option<String>,
    paging: AtomicBool,
}

struct Batch {
    entries: Vec<SearchEntry>,
    refs: Vec<String>,
    truncated: bool,
    warning: Option<String>,
}

impl Session {
    fn ctx(&self) -> Ctx<'_> {
        Ctx { host: &self.profile.host, ldaps: self.profile.scheme == Scheme::Ldaps, port: self.profile.port() }
    }

    pub fn info(&self) -> ConnInfo {
        let mut ncs = self.rootdse.naming_contexts();
        if ncs.is_empty() {
            ncs.push(self.base_dn.clone());
        }
        ConnInfo {
            flavor: self.flavor,
            base_dn: self.base_dn.clone(),
            naming_contexts: ncs,
            bound_as: self.bound_as.clone(),
            vendor: self.rootdse.first("vendorName").map(str::to_string),
            paging: self.paging.load(Ordering::Relaxed),
        }
    }

    pub fn is_closed(&self) -> bool {
        self.ldap.clone().is_closed()
    }

    pub async fn connect(profile: Profile, creds: Creds) -> Result<Session> {
        let ctx_err = |e: &ldap3::LdapError| {
            error::classify(
                e,
                &Ctx { host: &profile.host, ldaps: profile.scheme == Scheme::Ldaps, port: profile.port() },
            )
        };
        let mut settings = LdapConnSettings::new().set_conn_timeout(profile.timeout());
        if profile.scheme == Scheme::Ldaps {
            if profile.insecure_skip_verify {
                warn!(profile = %profile.name, "TLS certificate verification is DISABLED for this connection");
                settings = settings.set_no_tls_verify(true);
            } else if let Some(ca) = &profile.ca_cert {
                settings = settings.set_config(tls_config_with_ca(ca)?);
            }
        }
        let url = profile.url();
        info!(%url, "connecting");
        let connect = LdapConnAsync::with_settings(settings, &url);
        let (conn, mut ldap) = match tokio::time::timeout(profile.timeout(), connect).await {
            Ok(r) => r.map_err(|e| ctx_err(&e))?,
            Err(_) => {
                return Err(Failure::new(ErrorKind::Timeout, format!("Timed out connecting to {url}"))
                    .hint("check host, port and firewall; for LDAPS make sure the port speaks TLS"));
            }
        };
        tokio::spawn(async move {
            if let Err(e) = conn.drive().await {
                warn!("connection closed: {e}");
            }
        });

        let bound_as = match &creds {
            Creds::Anonymous => None,
            Creds::Simple { bind_dn, password } => {
                if password.expose_secret().is_empty() {
                    return Err(Failure::new(ErrorKind::InvalidCredentials, "Password is empty"));
                }
                if profile.scheme == Scheme::Ldap {
                    warn!(%bind_dn, "binding over plain LDAP: the password is sent unencrypted");
                }
                info!(%bind_dn, "binding");
                let res = ldap
                    .with_timeout(profile.timeout())
                    .simple_bind(bind_dn, password.expose_secret())
                    .await
                    .map_err(|e| ctx_err(&e))?;
                if res.rc != 0 {
                    return Err(error::from_result(&res));
                }
                Some(bind_dn.clone())
            }
        };

        let rootdse = match read_rootdse(&mut ldap, &profile).await {
            Ok(r) => r,
            Err(e) => {
                warn!("could not read RootDSE: {e}");
                RootDse::default()
            }
        };
        let flavor = flavor::resolve_flavor(profile.flavor, &rootdse);
        let base_dn = match profile.base_dn.clone().or_else(|| rootdse.default_base()) {
            Some(b) => b,
            None => {
                return Err(Failure::new(ErrorKind::Other, "Could not determine the base DN")
                    .hint("the server did not publish namingContexts; set \"base_dn\" in the profile"));
            }
        };
        let paging = rootdse.supports_control(PAGED_RESULTS_OID);
        info!(?flavor, %base_dn, paging, "connected");
        Ok(Session { ldap, profile, rootdse, flavor, base_dn, bound_as, paging: AtomicBool::new(paging) })
    }

    pub async fn unbind(&self) {
        let _ = self.ldap.clone().unbind().await;
    }

    pub async fn abandon(&self, msgid: i32) {
        if msgid > 0 {
            debug!(msgid, "abandoning");
            let _ = self.ldap.clone().abandon(msgid).await;
        }
    }

    /// Runs a search, stopping after `limit` entries. Uses paging when the server supports it,
    /// and falls back to an unpaged search (remembered for the session) if the control is rejected.
    async fn search_raw(
        &self,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: &[&str],
        limit: usize,
        slot: &MsgSlot,
    ) -> Result<Batch> {
        let paging = self.paging.load(Ordering::Relaxed);
        match self.search_once(base, scope, filter, attrs, limit, paging, slot).await {
            Err(f) if paging && matches!(f.rc, Some(12) | Some(2) | Some(53)) => {
                warn!("server rejected the paged results control ({}); retrying without paging", f.detail);
                self.paging.store(false, Ordering::Relaxed);
                self.search_once(base, scope, filter, attrs, limit, false, slot).await
            }
            r => r,
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn search_once(
        &self,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: &[&str],
        limit: usize,
        paging: bool,
        slot: &MsgSlot,
    ) -> Result<Batch> {
        debug!(%base, ?scope, %filter, ?attrs, limit, paging, "search");
        let mut ldap = self.ldap.clone();
        ldap.with_timeout(self.profile.timeout());
        let attrs: Vec<String> = attrs.iter().map(|s| s.to_string()).collect();
        let mut stream = if paging {
            let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![Box::new(PagedResults::new(self.profile.page_size))];
            ldap.streaming_search_with(adapters, base, scope, filter, attrs)
                .await
                .map_err(|e| error::classify(&e, &self.ctx()))?
        } else {
            let sizelimit = i32::try_from(limit.saturating_add(1)).unwrap_or(i32::MAX);
            ldap.with_search_options(SearchOptions::new().sizelimit(sizelimit));
            ldap.streaming_search(base, scope, filter, attrs).await.map_err(|e| error::classify(&e, &self.ctx()))?
        };
        slot.store(stream.ldap_handle().last_id(), Ordering::Relaxed);

        let mut batch = Batch { entries: Vec::new(), refs: Vec::new(), truncated: false, warning: None };
        loop {
            let next = stream.next().await;
            slot.store(stream.ldap_handle().last_id(), Ordering::Relaxed);
            let re: ResultEntry = match next {
                Ok(Some(re)) => re,
                Ok(None) => break,
                Err(e) => {
                    let _ = stream.finish().await;
                    return Err(error::classify(&e, &self.ctx()));
                }
            };
            if re.is_intermediate() {
                continue;
            }
            if re.is_ref() {
                batch.refs.extend(ldap3::parse_refs(re.0));
                continue;
            }
            if batch.entries.len() >= limit {
                batch.truncated = true;
                let id = stream.ldap_handle().last_id();
                let _ = stream.finish().await;
                self.abandon(id).await;
                return Ok(batch);
            }
            batch.entries.push(SearchEntry::construct(re));
        }
        let res = stream.finish().await;
        match res.rc {
            0 => {}
            4 => batch.truncated = true,
            3 => {
                batch.truncated = true;
                batch.warning = Some("the server's time limit was reached; results are partial".into());
            }
            11 => {
                batch.truncated = true;
                batch.warning = Some("the server's administrative limit was reached; results are partial".into());
            }
            10 => batch.refs.extend(res.refs.iter().cloned()),
            32 if scope != Scope::Base || !batch.entries.is_empty() => {}
            _ => return Err(error::from_result(&res)),
        }
        Ok(batch)
    }

    /// Reads one entry with all user and operational attributes, expanding ranged values.
    pub async fn read_entry(&self, dn: &str, slot: &MsgSlot) -> Result<Entry> {
        let mut attrs = vec!["*", "+"];
        if self.flavor != Flavor::Ad {
            // LLDAP only returns memberOf when asked for it by name.
            attrs.push("memberOf");
        }
        if self.flavor == Flavor::Ad {
            attrs.extend([
                "msDS-UserPasswordExpiryTimeComputed",
                "msDS-User-Account-Control-Computed",
                "canonicalName",
            ]);
        }
        let mut se = self.read_base(dn, &attrs, slot).await?;
        self.expand_ranges(&mut se, slot).await?;
        Ok(Entry::from_maps(se.dn, se.attrs, se.bin_attrs))
    }

    async fn read_base(&self, dn: &str, attrs: &[&str], slot: &MsgSlot) -> Result<SearchEntry> {
        if self.is_lldap_root(dn) {
            // LLDAP has no real root entry: a base search there returns every user and group.
            let mut attrs = std::collections::HashMap::new();
            attrs.insert("objectClass".to_string(), vec!["top".to_string(), "domain".to_string()]);
            attrs.insert("description".to_string(), vec!["(LLDAP root: synthesized by LdapTui)".to_string()]);
            return Ok(SearchEntry { dn: dn.to_string(), attrs, bin_attrs: Default::default() });
        }
        let batch = self.search_raw(dn, Scope::Base, "(objectClass=*)", attrs, 1, slot).await?;
        batch.entries.into_iter().next().filter(|e| model::dn_eq(&e.dn, dn)).ok_or_else(|| {
            Failure::new(ErrorKind::NoSuchObject, "No such entry, or no permission to read it").detail(dn.to_string())
        })
    }

    fn is_lldap_root(&self, dn: &str) -> bool {
        self.flavor == Flavor::Lldap && model::dn_eq(dn, &self.base_dn)
    }

    /// Fetches remaining chunks of any `attr;range=x-y` attributes and merges them.
    async fn expand_ranges(&self, se: &mut SearchEntry, slot: &MsgSlot) -> Result<()> {
        let ranged: Vec<String> = se.attrs.keys().filter(|k| range::parse(k).is_some()).cloned().collect();
        for name in ranged {
            let mut values = se.attrs.remove(&name).unwrap_or_default();
            let mut r = range::parse(&name).expect("checked above");
            let base = r.base.clone();
            let mut rounds = 0;
            while let Some(next_attr) = range::next_request(&r) {
                rounds += 1;
                if rounds > 10_000 {
                    warn!(attr = %base, "giving up on ranged retrieval after too many rounds");
                    break;
                }
                let chunk = self.read_base(&se.dn, &[next_attr.as_str()], slot).await?;
                let Some((k, v)) = chunk.attrs.into_iter().find(|(k, _)| range::parse(k).is_some()) else {
                    break;
                };
                values.extend(v);
                r = range::parse(&k).expect("matched");
            }
            debug!(attr = %base, count = values.len(), "ranged retrieval complete");
            se.attrs.entry(base).or_default().extend(values);
        }
        Ok(())
    }

    pub async fn list_children(
        &self,
        dn: &str,
        prefix: Option<&str>,
        limit: usize,
        slot: &MsgSlot,
    ) -> Result<ChildList> {
        if self.is_lldap_root(dn) {
            // LLDAP flattens one-level searches on the root; show its two fixed containers instead.
            let children = ["ou=groups", "ou=people"]
                .iter()
                .filter(|ou| prefix.is_none_or(|p| ou[3..].starts_with(&p.to_ascii_lowercase())))
                .map(|ou| Child {
                    dn: format!("{ou},{}", self.base_dn),
                    kind: EntryKind::OrgUnit,
                    has_children: Some(true),
                })
                .collect();
            return Ok(ChildList { children, referrals: vec![], truncated: false });
        }
        let filter = match prefix {
            Some(p) if !p.is_empty() => self.flavor.child_prefix_filter(p),
            _ => "(objectClass=*)".to_string(),
        };
        let batch =
            self.search_raw(dn, Scope::OneLevel, &filter, &["objectClass", "hasSubordinates"], limit, slot).await?;
        let mut children: Vec<Child> = batch
            .entries
            .into_iter()
            .map(|e| {
                let ocs: Vec<String> = attr_values(&e, "objectClass").iter().map(|s| s.to_ascii_lowercase()).collect();
                let has_children = attr_values(&e, "hasSubordinates").first().map(|v| v.eq_ignore_ascii_case("TRUE"));
                Child { kind: EntryKind::from_object_classes(&ocs), dn: e.dn, has_children }
            })
            .collect();
        children.sort_by_cached_key(|c| (c.kind.sort_rank(), model::rdn_value(&c.dn).to_lowercase()));
        Ok(ChildList { children, referrals: batch.refs, truncated: batch.truncated })
    }

    pub async fn search(&self, base: &str, scope: Scope, filter: &str, slot: &MsgSlot) -> Result<HitList> {
        self.search_with(base, scope, filter, &[], slot).await
    }

    /// Search returning summary rows plus the values of `extra` attributes (result columns).
    pub async fn search_with(
        &self,
        base: &str,
        scope: Scope,
        filter: &str,
        extra: &[String],
        slot: &MsgSlot,
    ) -> Result<HitList> {
        let limit = self.profile.size_limit as usize;
        let attrs = summary_attrs(extra);
        let attrs: Vec<&str> = attrs.iter().map(String::as_str).collect();
        let batch = self.search_raw(base, scope, filter, &attrs, limit, slot).await?;
        let mut hits: Vec<Hit> = batch.entries.iter().map(hit_from).collect();
        hits.sort_by_cached_key(|h| h.name.to_lowercase());
        Ok(HitList { hits, referrals: batch.refs, truncated: batch.truncated, warning: batch.warning })
    }

    pub async fn find_dn(&self, dn: &str, slot: &MsgSlot) -> Result<HitList> {
        self.find_dn_with(dn, &[], slot).await
    }

    /// Looks up an exact DN; if it doesn't exist, searches the base DN for its RDN value.
    pub async fn find_dn_with(&self, dn: &str, extra: &[String], slot: &MsgSlot) -> Result<HitList> {
        let attrs = summary_attrs(extra);
        let attrs: Vec<&str> = attrs.iter().map(String::as_str).collect();
        match self.read_base(dn, &attrs, slot).await {
            Ok(se) => Ok(HitList { hits: vec![hit_from(&se)], ..Default::default() }),
            Err(f) if f.kind == ErrorKind::NoSuchObject || f.rc == Some(34) => {
                let rdn = model::rdn(dn);
                let Some((attr, _)) = rdn.split_once('=') else { return Err(f) };
                let value = model::rdn_value(dn);
                if !filter::valid_attribute(attr.trim()) || value.is_empty() {
                    return Err(f);
                }
                let filt = format!("({}={})", attr.trim(), filter::escape(&value));
                let mut hl = self.search_with(&self.base_dn, Scope::Subtree, &filt, extra, slot).await?;
                hl.warning = Some(format!("\"{dn}\" does not exist; showing entries with {attr}={value}"));
                Ok(hl)
            }
            Err(f) => Err(f),
        }
    }

    pub async fn members(&self, dn: &str, slot: &MsgSlot) -> Result<HitList> {
        self.members_with(dn, &[], slot).await
    }

    /// Members of a group (`member`, `uniqueMember`, `memberUid`), plus AD primary-group members.
    pub async fn members_with(&self, dn: &str, extra: &[String], slot: &MsgSlot) -> Result<HitList> {
        let mut se =
            self.read_base(dn, &["member", "uniqueMember", "memberUid", "objectSid", "objectClass"], slot).await?;
        self.expand_ranges(&mut se, slot).await?;
        let mut dns: Vec<String> = attr_values(&se, "member").to_vec();
        dns.extend(attr_values(&se, "uniqueMember").iter().map(|v| strip_uid_suffix(v)));
        // Servers like LLDAP list each member in both member and uniqueMember.
        let mut seen = HashSet::new();
        dns.retain(|d| seen.insert(model::normalize_dn(d)));
        let mut out = self.resolve_dns(dns, extra, slot).await;

        let uids = attr_values(&se, "memberUid");
        if !uids.is_empty() {
            for chunk in uids.chunks(100) {
                let f =
                    format!("(|{})", chunk.iter().map(|u| format!("(uid={})", filter::escape(u))).collect::<String>());
                let mut hl = self.search_with(&self.base_dn, Scope::Subtree, &f, extra, slot).await?;
                let found: HashSet<String> = hl
                    .hits
                    .iter()
                    .flat_map(|h| [h.name.to_lowercase(), model::rdn_value(&h.dn).to_lowercase()])
                    .collect();
                for u in chunk {
                    if !found.contains(&u.to_lowercase()) {
                        hl.hits.push(Hit::bare(
                            "",
                            EntryKind::Other,
                            u.clone(),
                            "memberUid (no matching entry)".into(),
                        ));
                    }
                }
                out.hits.append(&mut hl.hits);
            }
        }

        if self.flavor == Flavor::Ad
            && let Some(sid) = se.bin_attrs.get("objectSid").and_then(|v| v.first())
            && let Some(rid) = decode::sid_to_string(sid).and_then(|s| s.rsplit('-').next()?.parse::<u32>().ok())
        {
            let f = format!("(primaryGroupID={rid})");
            let mut hl = self.search_with(&self.base_dn, Scope::Subtree, &f, extra, slot).await?;
            for h in hl.hits.iter_mut() {
                h.tag = Some("primary".into());
            }
            out.truncated |= hl.truncated;
            out.hits.append(&mut hl.hits);
        }
        out.hits.sort_by_cached_key(|h| h.name.to_lowercase());
        Ok(out)
    }

    pub async fn member_of(&self, dn: &str, nested: bool, slot: &MsgSlot) -> Result<HitList> {
        self.member_of_with(dn, nested, &[], slot).await
    }

    /// Groups the entry belongs to. With `nested`, includes groups reached through other groups.
    pub async fn member_of_with(&self, dn: &str, nested: bool, extra: &[String], slot: &MsgSlot) -> Result<HitList> {
        let mut se =
            self.read_base(dn, &["memberOf", "uid", "primaryGroupID", "objectSid", "objectClass"], slot).await?;
        self.expand_ranges(&mut se, slot).await?;
        let mut direct = self.direct_groups(&se, extra, slot).await?;
        let direct_set: HashSet<String> = direct.hits.iter().map(|h| model::normalize_dn(&h.dn)).collect();

        if self.flavor == Flavor::Ad
            && let Some(primary) = self.ad_primary_group(&se, extra, slot).await?
        {
            direct.hits.push(primary);
        }

        if nested && self.flavor.supports_nested_groups() {
            let nested_hits = if self.flavor == Flavor::Ad {
                let f = format!("(&(objectClass=group)(member:{IN_CHAIN_OID}:={}))", filter::escape(dn));
                self.search_with(&self.base_dn, Scope::Subtree, &f, extra, slot).await?.hits
            } else {
                self.nested_client_side(&direct.hits, extra, slot).await?
            };
            for mut h in nested_hits {
                let key = model::normalize_dn(&h.dn);
                if !direct_set.contains(&key) && !direct.hits.iter().any(|d| model::dn_eq(&d.dn, &h.dn)) {
                    h.tag = Some("nested".into());
                    direct.hits.push(h);
                }
            }
        }
        direct.hits.sort_by_cached_key(|h| (h.tag.is_some(), h.name.to_lowercase()));
        Ok(direct)
    }

    async fn direct_groups(&self, se: &SearchEntry, extra: &[String], slot: &MsgSlot) -> Result<HitList> {
        let member_of = attr_values(se, "memberOf");
        if self.flavor == Flavor::Ad {
            return Ok(self.resolve_dns(member_of.to_vec(), extra, slot).await);
        }
        // Outside AD, memberOf (if present at all) usually only covers groupOfNames/member, so
        // also search for groups that list this entry via member, uniqueMember or memberUid.
        let d = filter::escape(&se.dn);
        let mut f = format!("(|(member={d})(uniqueMember={d})");
        if let Some(uid) = attr_values(se, "uid").first() {
            f.push_str(&format!("(memberUid={})", filter::escape(uid)));
        }
        f.push(')');
        let mut hl = self.search_with(&self.base_dn, Scope::Subtree, &f, extra, slot).await?;
        let missing: Vec<String> =
            member_of.iter().filter(|m| !hl.hits.iter().any(|h| model::dn_eq(&h.dn, m))).cloned().collect();
        if !missing.is_empty() {
            hl.hits.extend(self.resolve_dns(missing, extra, slot).await.hits);
        }
        Ok(hl)
    }

    async fn ad_primary_group(&self, se: &SearchEntry, extra: &[String], slot: &MsgSlot) -> Result<Option<Hit>> {
        let Some(rid) = attr_values(se, "primaryGroupID").first().and_then(|v| v.parse::<u32>().ok()) else {
            return Ok(None);
        };
        let Some(sid) = se.bin_attrs.get("objectSid").and_then(|v| v.first()) else {
            return Ok(None);
        };
        let Some(gsid) = decode::primary_group_sid(sid, rid) else {
            return Ok(None);
        };
        let f = format!("(objectSid={})", decode::filter_escape_bytes(&gsid));
        let hl = self.search_with(&self.base_dn, Scope::Subtree, &f, extra, slot).await?;
        Ok(hl.hits.into_iter().next().map(|mut h| {
            h.tag = Some("primary".into());
            h
        }))
    }

    /// Breadth-first walk up the group graph, with cycle detection and a depth limit.
    async fn nested_client_side(&self, direct: &[Hit], extra: &[String], slot: &MsgSlot) -> Result<Vec<Hit>> {
        let mut seen: HashSet<String> = direct.iter().map(|h| model::normalize_dn(&h.dn)).collect();
        let mut frontier: Vec<String> = direct.iter().map(|h| h.dn.clone()).filter(|d| !d.is_empty()).collect();
        let mut out = Vec::new();
        for _ in 0..NESTED_DEPTH_LIMIT {
            if frontier.is_empty() {
                break;
            }
            let mut next = Vec::new();
            for g in frontier {
                let se = match self.read_base(&g, &["memberOf", "uid", "objectClass"], slot).await {
                    Ok(se) => se,
                    Err(_) => continue,
                };
                for h in self.direct_groups(&se, extra, slot).await?.hits {
                    if seen.insert(model::normalize_dn(&h.dn)) {
                        next.push(h.dn.clone());
                        out.push(h);
                    }
                }
            }
            frontier = next;
        }
        Ok(out)
    }

    /// Resolves DNs to summary rows with bounded concurrency. Unresolvable DNs are kept as bare rows.
    async fn resolve_dns(&self, dns: Vec<String>, extra: &[String], slot: &MsgSlot) -> HitList {
        let total = dns.len();
        let take = total.min(RESOLVE_CAP);
        let attrs = summary_attrs(extra);
        let attrs: Vec<&str> = attrs.iter().map(String::as_str).collect();
        let attrs = &attrs;
        let mut hits: Vec<Hit> = futures::stream::iter(dns.iter().take(take).cloned())
            .map(|dn| async move {
                match self.read_base(&dn, attrs, slot).await {
                    Ok(se) => hit_from(&se),
                    Err(f) => bare_hit(&dn, &f.title),
                }
            })
            .buffered(16)
            .collect()
            .await;
        hits.extend(dns.iter().skip(take).map(|dn| bare_hit(dn, "not resolved")));
        let warning = (total > take).then(|| format!("{total} entries; details loaded for the first {take}"));
        HitList { hits, referrals: vec![], truncated: false, warning }
    }
}

async fn read_rootdse(ldap: &mut Ldap, profile: &Profile) -> Result<RootDse> {
    let res = ldap
        .with_timeout(profile.timeout())
        .search("", Scope::Base, "(objectClass=*)", ROOTDSE_ATTRS)
        .await
        .map_err(|e| Failure::other(e.to_string()))?;
    let (entries, _) = res.success().map_err(|e| Failure::other(e.to_string()))?;
    let se = entries.into_iter().next().map(SearchEntry::construct);
    Ok(RootDse { attrs: se.map(|e| e.attrs).unwrap_or_default() })
}

fn tls_config_with_ca(path: &std::path::Path) -> Result<Arc<rustls::ClientConfig>> {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(path).and_then(|it| it.collect::<std::result::Result<Vec<_>, _>>()).map_err(
            |e| Failure::new(ErrorKind::Tls, format!("Cannot read ca_cert {}", path.display())).detail(e.to_string()),
        )?;
    if certs.is_empty() {
        return Err(Failure::new(ErrorKind::Tls, format!("ca_cert {} contains no certificates", path.display())));
    }
    for c in certs {
        roots.add(c).map_err(|e| {
            Failure::new(ErrorKind::Tls, format!("Invalid certificate in {}", path.display())).detail(e.to_string())
        })?;
    }
    let cfg = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    Ok(Arc::new(cfg))
}

fn attr_values<'a>(se: &'a SearchEntry, name: &str) -> &'a [String] {
    se.attrs.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_slice()).unwrap_or(&[])
}

/// `uniqueMember` may carry an optional `#'0101'B` UID suffix.
fn strip_uid_suffix(v: &str) -> String {
    match v.rfind("#'") {
        Some(i) if v.ends_with("'B") => v[..i].to_string(),
        _ => v.to_string(),
    }
}

/// Summary attributes plus any extra ones, without duplicates or virtual column names.
fn summary_attrs(extra: &[String]) -> Vec<String> {
    let mut out: Vec<String> = SUMMARY_ATTRS.iter().map(|s| s.to_string()).collect();
    for e in extra {
        if filter::valid_attribute(e) && !out.iter().any(|o| o.eq_ignore_ascii_case(e)) {
            out.push(e.clone());
        }
    }
    out
}

pub fn hit_from(se: &SearchEntry) -> Hit {
    let first = |names: &[&str]| names.iter().find_map(|n| attr_values(se, n).first().cloned());
    let ocs: Vec<String> = attr_values(se, "objectClass").iter().map(|s| s.to_ascii_lowercase()).collect();
    let mut values: std::collections::HashMap<String, Vec<model::Value>> = std::collections::HashMap::new();
    let mut partial = Vec::new();
    for (k, vs) in &se.attrs {
        let (base, ranged) = split_range(k);
        if ranged {
            partial.push(base.clone());
        }
        let bin = model::is_binary_attr(&base);
        values.entry(base).or_default().extend(
            vs.iter().map(|v| {
                if bin { model::Value::Binary(v.clone().into_bytes()) } else { model::Value::Text(v.clone()) }
            }),
        );
    }
    for (k, vs) in &se.bin_attrs {
        let (base, ranged) = split_range(k);
        if ranged {
            partial.push(base.clone());
        }
        values.entry(base).or_default().extend(vs.iter().cloned().map(model::Value::Binary));
    }
    Hit {
        dn: se.dn.clone(),
        kind: EntryKind::from_object_classes(&ocs),
        name: first(&["displayName", "cn", "uid", "name", "ou"]).unwrap_or_else(|| model::rdn_value(&se.dn)),
        detail: first(&["mail", "sAMAccountName", "description"]).unwrap_or_default(),
        tag: None,
        values,
        partial,
    }
}

/// `member;range=0-1499` -> (`member`, true).
fn split_range(name: &str) -> (String, bool) {
    match name.split_once(";range=") {
        Some((b, _)) => (b.to_ascii_lowercase(), true),
        None => (name.to_ascii_lowercase(), false),
    }
}

fn bare_hit(dn: &str, why: &str) -> Hit {
    Hit::bare(dn, EntryKind::Other, model::rdn_value(dn), format!("({why})"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_member_suffix() {
        assert_eq!(strip_uid_suffix("cn=a,dc=b#'0101'B"), "cn=a,dc=b");
        assert_eq!(strip_uid_suffix("cn=a#b,dc=c"), "cn=a#b,dc=c");
    }

    #[test]
    fn creds_debug_redacts() {
        let c = Creds::Simple { bind_dn: "cn=a".into(), password: SecretString::from("hunter2") };
        let s = format!("{c:?}");
        assert!(!s.contains("hunter2"));
    }
}
