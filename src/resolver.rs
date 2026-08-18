use std::collections::HashSet;
use std::time::Duration;

use hickory_resolver::config::ResolverOpts;
use hickory_resolver::TokioResolver;
use rand::Rng;

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

/// Builds a tokio resolver from system config with a per-query timeout.
pub fn build_resolver(timeout: Duration) -> Result<TokioResolver, String> {
    let mut opts = ResolverOpts::default();
    opts.timeout = timeout;
    TokioResolver::builder_tokio()
        .map_err(|e| format!("build resolver: {e}"))?
        .with_options(opts)
        .build()
        .map_err(|e| format!("build resolver: {e}"))
}

/// Performs a dual-stack lookup, returning IPs or `None` on any failure.
pub async fn lookup(
    resolver: &TokioResolver,
    fqdn: &str,
    timeout: Duration,
) -> Option<Vec<String>> {
    match tokio::time::timeout(timeout, resolver.lookup_ip(fqdn)).await {
        Ok(Ok(lookup)) => {
            let ips: Vec<String> = lookup.iter().map(|ip| ip.to_string()).collect();
            if ips.is_empty() {
                None
            } else {
                Some(ips)
            }
        }
        _ => None,
    }
}

/// Detects wildcards by probing a random subdomain.
pub async fn detect_wildcards(
    resolver: &TokioResolver,
    domain: &str,
    timeout: Duration,
) -> Vec<String> {
    let fqdn = format!("{}.{}", random_subdomain(12), domain);
    lookup(resolver, &fqdn, timeout).await.unwrap_or_default()
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
}
