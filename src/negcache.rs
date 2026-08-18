use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Maximum entries in the negative cache.
const MAX_ENTRIES: usize = 100_000;

struct Inner {
    cache: HashMap<String, Instant>,
    order: VecDeque<String>,
}

/// Thread-safe negative DNS cache with FIFO eviction and TTL.
pub struct NegCache {
    inner: Mutex<Inner>,
    ttl: Duration,
}

impl NegCache {
    /// Creates a cache with the given TTL. A zero TTL disables caching.
    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(Inner {
                cache: HashMap::new(),
                order: VecDeque::new(),
            }),
            ttl,
        }
    }

    /// Returns true if the FQDN is cached and not expired.
    pub fn is_cached(&self, fqdn: &str) -> bool {
        if self.ttl.is_zero() {
            return false;
        }
        let inner = self.inner.lock().unwrap();
        match inner.cache.get(fqdn) {
            Some(expire) => Instant::now() < *expire,
            None => false,
        }
    }

    /// Adds an FQDN to the cache, evicting the oldest entries at capacity.
    pub fn add(&self, fqdn: String) {
        if self.ttl.is_zero() {
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        while inner.cache.len() >= MAX_ENTRIES {
            match inner.order.pop_front() {
                Some(oldest) => {
                    inner.cache.remove(&oldest);
                }
                None => break,
            }
        }
        inner.cache.insert(fqdn.clone(), Instant::now() + self.ttl);
        inner.order.push_back(fqdn);
    }

    /// Removes expired entries.
    pub fn cleanup(&self) {
        if self.ttl.is_zero() {
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        let now = Instant::now();
        let expired: HashSet<String> = inner
            .order
            .iter()
            .filter(|fqdn| match inner.cache.get(*fqdn) {
                Some(expire) => now >= *expire,
                None => true,
            })
            .cloned()
            .collect();
        for fqdn in &expired {
            inner.cache.remove(fqdn);
        }
        inner.order.retain(|f| !expired.contains(f));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caches_hit_within_ttl() {
        let c = NegCache::new(Duration::from_secs(60));
        c.add("a.example.com".into());
        assert!(c.is_cached("a.example.com"));
    }

    #[test]
    fn expires_after_ttl() {
        let c = NegCache::new(Duration::from_millis(10));
        c.add("a.example.com".into());
        std::thread::sleep(Duration::from_millis(30));
        assert!(!c.is_cached("a.example.com"));
    }

    #[test]
    fn evicts_oldest_at_capacity() {
        let c = NegCache::new(Duration::from_secs(60));
        for i in 0..MAX_ENTRIES {
            c.add(format!("{i}.example.com"));
        }
        // At capacity: adding one more evicts the oldest.
        c.add("new.example.com".into());
        assert!(!c.is_cached("0.example.com"));
        assert!(c.is_cached("new.example.com"));
    }

    #[test]
    fn zero_ttl_disables_cache() {
        let c = NegCache::new(Duration::ZERO);
        c.add("a.example.com".into());
        assert!(!c.is_cached("a.example.com"));
    }

    #[test]
    fn cleanup_removes_expired() {
        let c = NegCache::new(Duration::from_millis(10));
        c.add("a.example.com".into());
        c.add("b.example.com".into());
        std::thread::sleep(Duration::from_millis(30));
        c.cleanup();
        assert!(!c.is_cached("a.example.com"));
        assert!(!c.is_cached("b.example.com"));
    }
}
