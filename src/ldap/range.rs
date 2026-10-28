//! Active Directory ranged attribute retrieval (`member;range=0-1499`).

/// A parsed `attr;range=low-high` attribute name. `high == None` means `*` (final chunk).
#[derive(Debug, PartialEq, Eq)]
pub struct RangedName {
    pub base: String,
    pub low: u32,
    pub high: Option<u32>,
}

pub fn parse(name: &str) -> Option<RangedName> {
    let lower = name.to_ascii_lowercase();
    let idx = lower.find(";range=")?;
    let base = name[..idx].to_string();
    let spec = &name[idx + ";range=".len()..];
    let (lo, hi) = spec.split_once('-')?;
    let low = lo.parse().ok()?;
    let high = if hi == "*" { None } else { Some(hi.parse().ok()?) };
    Some(RangedName { base, low, high })
}

/// The attribute to request for the next chunk, or `None` when retrieval is complete.
pub fn next_request(r: &RangedName) -> Option<String> {
    r.high.map(|h| format!("{};range={}-*", r.base, h + 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses() {
        assert_eq!(parse("member;range=0-1499"), Some(RangedName { base: "member".into(), low: 0, high: Some(1499) }));
        assert_eq!(parse("member;Range=1500-*"), Some(RangedName { base: "member".into(), low: 1500, high: None }));
        assert_eq!(parse("member"), None);
        assert_eq!(parse("member;range=a-b"), None);
    }

    #[test]
    fn next_chunk() {
        assert_eq!(next_request(&parse("member;range=0-1499").unwrap()).unwrap(), "member;range=1500-*");
        assert_eq!(next_request(&parse("member;range=1500-*").unwrap()), None);
    }
}
