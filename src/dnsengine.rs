//! Raw UDP DNS engine (massdns-style): builds DNS queries with `hickory-proto`,
//! sends them over UDP sockets, retries on timeout/SERVFAIL, falls back to TCP
//! on truncated responses, and distributes queries across a resolver pool.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use rand::Rng;
use tokio::net::UdpSocket;

/// A parsed DNS response: IPs found plus an optional CNAME target.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct DnsResponse {
    pub ips: Vec<String>,
    pub cname: Option<String>,
}

/// Pool of resolvers with round-robin distribution.
pub struct ResolverPool {
    resolvers: Vec<SocketAddr>,
    next: AtomicUsize,
}

impl Clone for ResolverPool {
    fn clone(&self) -> Self {
        Self {
            resolvers: self.resolvers.clone(),
            next: AtomicUsize::new(self.next.load(Ordering::Relaxed)),
        }
    }
}

impl ResolverPool {
    /// Creates a pool from a list of resolver addresses.
    pub fn new(resolvers: Vec<SocketAddr>) -> Self {
        Self {
            resolvers,
            next: AtomicUsize::new(0),
        }
    }

    /// Returns the next resolver in round-robin order, or `None` when empty.
    pub fn next(&self) -> Option<SocketAddr> {
        if self.resolvers.is_empty() {
            return None;
        }
        let idx = self.next.fetch_add(1, Ordering::Relaxed) % self.resolvers.len();
        Some(self.resolvers[idx])
    }

    /// Number of resolvers in the pool.
    pub fn is_empty(&self) -> bool {
        self.resolvers.is_empty()
    }
}

/// Parses a resolver string: bare IP, `IP:port`, or `[IPv6]:port`.
pub fn parse_resolver(s: &str) -> Result<SocketAddr, String> {
    let s = s.trim();
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 53));
    }
    if let Some(rest) = s.strip_prefix('[') {
        if let Some((ip, port)) = rest.split_once("]:") {
            if let (Ok(ip), Ok(port)) = (ip.parse::<IpAddr>(), port.parse::<u16>()) {
                return Ok(SocketAddr::new(ip, port));
            }
        }
    } else if let Some((ip, port)) = s.rsplit_once(':') {
        if let (Ok(ip), Ok(port)) = (ip.parse::<IpAddr>(), port.parse::<u16>()) {
            return Ok(SocketAddr::new(ip, port));
        }
    }
    Err(format!("invalid resolver: {s}"))
}

/// Loads resolvers from the system configuration.
///
/// Unix: parses `/etc/resolv.conf` (`nameserver` lines). Windows has no
/// resolv.conf, so it falls back to well-known public resolvers.
pub fn load_system_resolvers() -> Vec<SocketAddr> {
    #[cfg(unix)]
    {
        let content = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
        content
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                let rest = line.strip_prefix("nameserver")?.trim();
                parse_resolver(rest).ok()
            })
            .collect()
    }
    #[cfg(not(unix))]
    {
        vec![
            SocketAddr::new(IpAddr::from([8, 8, 8, 8]), 53),
            SocketAddr::new(IpAddr::from([1, 1, 1, 1]), 53),
        ]
    }
}

/// Loads resolvers from a file (one IP or IP:port per line, `#` comments).
pub fn load_resolvers_file(path: &str) -> Result<Vec<SocketAddr>, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("read resolvers file {path}: {e}"))?;
    let resolvers: Vec<SocketAddr> = content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| parse_resolver(l).ok())
        .collect();
    if resolvers.is_empty() {
        return Err(format!("no valid resolvers in {path}"));
    }
    Ok(resolvers)
}

/// Builds a DNS query message for the given name and record type.
pub fn build_query(name: &str, qtype: RecordType, id: u16) -> Result<Vec<u8>, String> {
    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    let fqdn = Name::from_ascii(name).map_err(|e| format!("invalid name {name}: {e}"))?;
    msg.add_query(Query::query(fqdn, qtype));
    msg.metadata.recursion_desired = true;
    msg.to_vec().map_err(|e| format!("encode query: {e}"))
}

/// Sends a query over UDP and waits for a response with a matching ID.
async fn query_udp(
    sock: &UdpSocket,
    resolver: SocketAddr,
    query: &[u8],
    id: u16,
    timeout: Duration,
) -> Result<Message, String> {
    sock.send_to(query, resolver)
        .await
        .map_err(|e| format!("udp send: {e}"))?;
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, _from) = tokio::time::timeout(timeout, sock.recv_from(&mut buf))
            .await
            .map_err(|_| "timeout".to_string())?
            .map_err(|e| format!("udp recv: {e}"))?;
        let msg = Message::from_vec(&buf[..n]).map_err(|e| format!("decode response: {e}"))?;
        if msg.id == id {
            return Ok(msg);
        }
        // Ignore responses with a mismatched ID (from another resolver).
    }
}

/// Sends a query over TCP using the 2-byte length prefix framing (RFC 1035 §4.2.2).
async fn query_tcp(
    resolver: SocketAddr,
    query: &[u8],
    timeout: Duration,
) -> Result<Message, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut sock = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(resolver))
        .await
        .map_err(|_| "tcp connect timeout".to_string())?
        .map_err(|e| format!("tcp connect: {e}"))?;
    let len = u16::try_from(query.len()).map_err(|_| "query too long".to_string())?;
    sock.write_all(&len.to_be_bytes())
        .await
        .map_err(|e| format!("tcp write len: {e}"))?;
    sock.write_all(query)
        .await
        .map_err(|e| format!("tcp write: {e}"))?;

    let mut len_buf = [0u8; 2];
    tokio::time::timeout(timeout, sock.read_exact(&mut len_buf))
        .await
        .map_err(|_| "tcp read len timeout".to_string())?
        .map_err(|e| format!("tcp read len: {e}"))?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    tokio::time::timeout(timeout, sock.read_exact(&mut resp))
        .await
        .map_err(|_| "tcp read timeout".to_string())?
        .map_err(|e| format!("tcp read: {e}"))?;
    Message::from_vec(&resp).map_err(|e| format!("decode tcp response: {e}"))
}

/// Extracts IPs and CNAME target from a response message.
fn extract_response(msg: &Message) -> Option<DnsResponse> {
    let mut ips = Vec::new();
    let mut cname = None;
    for rec in &msg.answers {
        match &rec.data {
            RData::A(ip) => ips.push((**ip).to_string()),
            RData::AAAA(ip) => ips.push((**ip).to_string()),
            RData::CNAME(name) => {
                cname = Some((**name).to_string().trim_end_matches('.').to_string());
            }
            _ => {}
        }
    }
    if ips.is_empty() && cname.is_none() {
        None
    } else {
        Some(DnsResponse { ips, cname })
    }
}

/// The raw DNS engine: resolver pool, per-query timeout, retry, TCP fallback.
#[derive(Clone)]
pub struct DnsEngine {
    pool: ResolverPool,
    timeout: Duration,
    attempts: usize,
}

impl DnsEngine {
    /// Creates an engine. `attempts` is clamped to at least 1.
    pub fn new(pool: ResolverPool, timeout: Duration, attempts: usize) -> Self {
        Self {
            pool,
            timeout,
            attempts: attempts.max(1),
        }
    }

    /// Performs a lookup for `name` of the given record type. Creates a fresh
    /// UDP socket per query so concurrent queries never race on a shared
    /// socket (packet stealing with mismatched transaction IDs). Returns
    /// `Ok(None)` for NXDOMAIN, no-answer, or exhausted retries.
    pub async fn lookup(
        &self,
        name: &str,
        qtype: RecordType,
    ) -> Result<Option<DnsResponse>, String> {
        let sock = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| format!("bind udp: {e}"))?;
        for _ in 0..self.attempts {
            let resolver = match self.pool.next() {
                Some(r) => r,
                None => return Err("no resolvers available".into()),
            };
            let id: u16 = rand::rng().random();
            let query = build_query(name, qtype, id)?;
            match query_udp(&sock, resolver, &query, id, self.timeout).await {
                Ok(msg) => {
                    if msg.truncation {
                        return match query_tcp(resolver, &query, self.timeout).await {
                            Ok(tcp_msg) => Ok(extract_response(&tcp_msg)),
                            Err(_) => Ok(None),
                        };
                    }
                    match msg.response_code {
                        ResponseCode::NoError => return Ok(extract_response(&msg)),
                        ResponseCode::NXDomain => return Ok(None),
                        ResponseCode::ServFail => continue, // retry with next resolver
                        _ => return Ok(None),
                    }
                }
                Err(_) => continue, // timeout or send/recv error: retry
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::{A, AAAA, CNAME};
    use hickory_proto::rr::Record;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn build_query_produces_parseable_bytes() {
        let bytes = build_query("a.example.com", RecordType::A, 0x1234).unwrap();
        let msg = Message::from_vec(&bytes).unwrap();
        assert_eq!(msg.id, 0x1234);
        assert_eq!(msg.queries.len(), 1);
        assert_eq!(msg.queries[0].query_type(), RecordType::A);
    }

    #[test]
    fn parse_resolver_handles_ip_port_and_v6() {
        assert_eq!(
            parse_resolver("8.8.8.8").unwrap(),
            SocketAddr::new(IpAddr::from([8, 8, 8, 8]), 53)
        );
        assert_eq!(
            parse_resolver("8.8.8.8:5353").unwrap(),
            SocketAddr::new(IpAddr::from([8, 8, 8, 8]), 5353)
        );
        assert_eq!(
            parse_resolver("[2001:db8::1]:5353").unwrap(),
            SocketAddr::new(IpAddr::from([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]), 5353)
        );
        assert!(parse_resolver("not-an-ip").is_err());
    }

    #[test]
    fn round_robin_distributes_across_resolvers() {
        let pool = ResolverPool::new(vec![
            SocketAddr::new(IpAddr::from([1, 1, 1, 1]), 53),
            SocketAddr::new(IpAddr::from([2, 2, 2, 2]), 53),
        ]);
        assert_eq!(pool.next().unwrap().ip().to_string(), "1.1.1.1");
        assert_eq!(pool.next().unwrap().ip().to_string(), "2.2.2.2");
        assert_eq!(pool.next().unwrap().ip().to_string(), "1.1.1.1");
    }

    #[test]
    fn empty_pool_returns_none() {
        let pool = ResolverPool::new(vec![]);
        assert!(pool.is_empty());
        assert!(pool.next().is_none());
    }

    #[test]
    fn extract_response_collects_ips_and_cname() {
        let mut msg = Message::new(1, MessageType::Response, OpCode::Query);
        msg.add_answer(Record::from_rdata(
            Name::from_ascii("a.example.com.").unwrap(),
            60,
            RData::CNAME(CNAME(Name::from_ascii("target.example.com.").unwrap())),
        ));
        msg.add_answer(Record::from_rdata(
            Name::from_ascii("target.example.com.").unwrap(),
            60,
            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
        ));
        msg.add_answer(Record::from_rdata(
            Name::from_ascii("target.example.com.").unwrap(),
            60,
            RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
        ));

        let resp = extract_response(&msg).unwrap();
        assert_eq!(resp.cname.as_deref(), Some("target.example.com"));
        assert_eq!(resp.ips, vec!["1.2.3.4".to_string(), "::1".to_string()]);
    }

    #[test]
    fn extract_response_none_when_empty() {
        let msg = Message::new(1, MessageType::Response, OpCode::Query);
        assert!(extract_response(&msg).is_none());
    }
}
