//! DNS resolution over the raw UDP engine, with robust wildcard detection
//! (N probes) and CNAME handling.

use std::collections::HashSet;

use hickory_proto::rr::RecordType;
use rand::Rng;

use crate::dnsengine::{DnsEngine, DnsResponse};

/// Number of random probes used for wildcard detection.
pub const WILDCARD_PROBES: usize = 3;

/// Detects and filters wildcard DNS responses.
pub struct WildcardDetector {
    ips: HashSet<String>,
}

impl WildcardDetector {
    /// Creates a detector from a set of wildcard IPs (possibly empty).
    pub fn new(ips: Vec<String>) -> Self {
        Self {
            ips: ips.into_iter().collect(),
        }
    }

    /// Returns true if a wildcard pattern was detected.
    pub fn has_wildcard(&self) -> bool {
        !self.ips.is_empty()
    }

    /// Returns true when all IPs belong to the wildcard pattern.
    pub fn is_wildcard_response(&self, ips: &[String]) -> bool {
        if self.ips.is_empty() || ips.is_empty() {
            return false;
        }
        ips.iter().all(|ip| self.ips.contains(ip))
    }
}

/// Result of a resolved subdomain: IPs plus an optional CNAME target.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct LookupResult {
    pub ips: Vec<String>,
    pub cname: Option<String>,
}

/// Performs a dual-stack lookup (A + AAAA in parallel) with CNAME handling.
///
/// Each record type uses its own fresh socket inside the engine, so parallel
/// queries never race on a shared socket. When a response carries only a CNAME
/// (no IPs), the target is followed one level to collect its addresses.
pub async fn lookup(engine: &DnsEngine, fqdn: &str) -> Option<LookupResult> {
    let (a, aaaa) = tokio::join!(
        engine.lookup(fqdn, RecordType::A),
        engine.lookup(fqdn, RecordType::AAAA),
    );
    let mut result = merge(a, aaaa);
    if result.ips.is_empty() {
        if let Some(cname) = result.cname.clone() {
            let (a2, aaaa2) = tokio::join!(
                engine.lookup(&cname, RecordType::A),
                engine.lookup(&cname, RecordType::AAAA),
            );
            result.ips = merge(a2, aaaa2).ips;
        }
    }
    if result.ips.is_empty() {
        None
    } else {
        Some(result)
    }
}

/// Merges the A and AAAA lookup responses into a single result.
fn merge(
    a: Result<Option<DnsResponse>, String>,
    aaaa: Result<Option<DnsResponse>, String>,
) -> LookupResult {
    let mut ips = Vec::new();
    let mut cname = None;
    for resp in [a, aaaa] {
        if let Ok(Some(resp)) = resp {
            ips.extend(resp.ips);
            if resp.cname.is_some() {
                cname = resp.cname;
            }
        }
    }
    LookupResult { ips, cname }
}

/// Detects wildcards by probing N random subdomains and unioning their IPs.
pub async fn detect_wildcards(engine: &DnsEngine, domain: &str) -> Vec<String> {
    let mut ips: Vec<String> = Vec::new();
    for _ in 0..WILDCARD_PROBES {
        let fqdn = format!("{}.{}", random_subdomain(12), domain);
        if let Some(res) = lookup(engine, &fqdn).await {
            for ip in res.ips {
                if !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
        }
    }
    ips
}

/// Generates a random subdomain string from the alphabet.
fn random_subdomain(len: usize) -> String {
    let mut rng = rand::rng();
    (0..len)
        .map(|_| {
            crate::generator::ALPHABET[rng.random_range(0..crate::generator::ALPHABET.len())]
                as char
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_wildcard_when_empty() {
        let wd = WildcardDetector::new(vec![]);
        assert!(!wd.has_wildcard());
        assert!(!wd.is_wildcard_response(&["1.2.3.4".into()]));
    }

    #[test]
    fn filters_full_wildcard_match() {
        let wd = WildcardDetector::new(vec!["10.0.0.1".into()]);
        assert!(wd.is_wildcard_response(&["10.0.0.1".into()]));
    }

    #[test]
    fn keeps_partial_wildcard_match() {
        let wd = WildcardDetector::new(vec!["10.0.0.1".into()]);
        assert!(!wd.is_wildcard_response(&["10.0.0.1".into(), "1.2.3.4".into()]));
    }

    #[test]
    fn keeps_non_wildcard() {
        let wd = WildcardDetector::new(vec!["10.0.0.1".into()]);
        assert!(!wd.is_wildcard_response(&["1.2.3.4".into()]));
    }

    #[test]
    fn random_subdomain_uses_alphabet() {
        let s = random_subdomain(12);
        assert_eq!(s.len(), 12);
        assert!(s.bytes().all(|b| crate::generator::ALPHABET.contains(&b)));
    }

    #[test]
    fn merge_combines_ips_and_cname() {
        let a = Ok(Some(DnsResponse {
            ips: vec!["1.2.3.4".to_string()],
            cname: Some("t.example.com".to_string()),
        }));
        let aaaa = Ok(Some(DnsResponse {
            ips: vec!["::1".to_string()],
            cname: None,
        }));
        let r = merge(a, aaaa);
        assert_eq!(r.ips, vec!["1.2.3.4".to_string(), "::1".to_string()]);
        assert_eq!(r.cname.as_deref(), Some("t.example.com"));
    }

    #[test]
    fn merge_ignores_errors() {
        let a: Result<Option<DnsResponse>, String> = Err("timeout".to_string());
        let aaaa = Ok(Some(DnsResponse {
            ips: vec!["1.2.3.4".to_string()],
            cname: None,
        }));
        let r = merge(a, aaaa);
        assert_eq!(r.ips, vec!["1.2.3.4".to_string()]);
    }
}
