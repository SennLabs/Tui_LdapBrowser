//! Search filter construction and escaping (RFC 4515).

use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum FilterError {
    #[error("enter an expression like  attribute=value  (operators: =  >=  <=  ~=)")]
    MissingOperator,
    #[error("\"{0}\" is not a valid attribute name")]
    BadAttribute(String),
    #[error("invalid filter syntax")]
    Syntax,
    #[error("search text is empty")]
    Empty,
}

/// Escapes a literal for use as an assertion value (`*`, `(`, `)`, `\`, NUL).
pub fn escape(v: &str) -> String {
    ldap3::ldap_escape(v).into_owned()
}

/// Escapes everything except `*`, which stays a wildcard.
pub fn escape_keep_wildcards(v: &str) -> String {
    v.split('*').map(escape).collect::<Vec<_>>().join("*")
}

/// Substitutes `{q}` in a filter template with the escaped query.
pub fn from_template(template: &str, q: &str) -> String {
    template.replace("{q}", &escape(q))
}

/// Attribute descriptor: a name (`letter *(letter/digit/-)`) or numeric OID, plus `;options`.
pub fn valid_attribute(a: &str) -> bool {
    let mut parts = a.split(';');
    let base = parts.next().unwrap_or("");
    let name_ok = base.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && base.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    let oid_ok = !base.is_empty() && base.split('.').all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
    (name_ok || oid_ok)
        && parts.all(|o| !o.is_empty() && o.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '='))
}

/// Builds a filter from `attr<op>value` input. `*` in the value is a wildcard.
pub fn attribute_filter(input: &str) -> Result<String, FilterError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(FilterError::Empty);
    }
    let input = input.strip_prefix('(').and_then(|s| s.strip_suffix(')')).unwrap_or(input);
    let (pos, op) = [">=", "<=", "~="]
        .iter()
        .filter_map(|op| input.find(op).map(|p| (p, *op)))
        .chain(input.find('=').map(|p| (p, "=")))
        .min_by_key(|(p, _)| *p)
        .ok_or(FilterError::MissingOperator)?;
    let attr = input[..pos].trim();
    let value = input[pos + op.len()..].trim();
    if !valid_attribute(attr) {
        return Err(FilterError::BadAttribute(attr.to_string()));
    }
    let value = if op == "=" { escape_keep_wildcards(value) } else { escape(value) };
    let f = format!("({attr}{op}{value})");
    validate(&f)?;
    Ok(f)
}

/// Normalises and checks a raw filter typed by the user. Adds outer parentheses if missing.
pub fn raw_filter(input: &str) -> Result<String, FilterError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(FilterError::Empty);
    }
    let f = if input.starts_with('(') { input.to_string() } else { format!("({input})") };
    validate(&f)?;
    Ok(f)
}

pub fn validate(f: &str) -> Result<(), FilterError> {
    ldap3::parse_filter(f).map(|_| ()).map_err(|_| FilterError::Syntax)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping() {
        assert_eq!(escape("a*b(c)\\"), r"a\2ab\28c\29\5c");
        assert_eq!(escape_keep_wildcards("jo*n (x)"), r"jo*n \28x\29");
    }

    #[test]
    fn template() {
        assert_eq!(from_template("(&(cn=*{q}*)(uid=*{q}*))", "a*)"), r"(&(cn=*a\2a\29*)(uid=*a\2a\29*))");
    }

    #[test]
    fn attribute_filters() {
        assert_eq!(attribute_filter("mail=*@example.com").unwrap(), "(mail=*@example.com)");
        assert_eq!(attribute_filter(" sn = Smith ").unwrap(), "(sn=Smith)");
        assert_eq!(attribute_filter("uidNumber>=1000").unwrap(), "(uidNumber>=1000)");
        assert_eq!(attribute_filter("(cn=a(b)").unwrap(), r"(cn=a\28b)");
        assert_eq!(attribute_filter("description=x=y").unwrap(), "(description=x=y)");
        assert_eq!(attribute_filter("cn"), Err(FilterError::MissingOperator));
        assert!(matches!(attribute_filter("bad attr=x"), Err(FilterError::BadAttribute(_))));
        assert_eq!(attribute_filter(""), Err(FilterError::Empty));
    }

    #[test]
    fn attribute_names() {
        assert!(valid_attribute("cn"));
        assert!(valid_attribute("msDS-UserPasswordExpiryTimeComputed"));
        assert!(valid_attribute("2.5.4.3"));
        assert!(valid_attribute("userCertificate;binary"));
        assert!(!valid_attribute("1cn"));
        assert!(!valid_attribute("c n"));
        assert!(!valid_attribute(""));
    }

    #[test]
    fn raw_filters() {
        assert_eq!(raw_filter("objectClass=*").unwrap(), "(objectClass=*)");
        assert_eq!(raw_filter("(&(a=1)(b=2))").unwrap(), "(&(a=1)(b=2))");
        assert_eq!(raw_filter("(&(a=1)"), Err(FilterError::Syntax));
        assert_eq!(
            raw_filter("(member:1.2.840.113556.1.4.1941:=cn=x,dc=y)").unwrap(),
            "(member:1.2.840.113556.1.4.1941:=cn=x,dc=y)"
        );
    }
}
