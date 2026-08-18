use std::time::Duration;

use clap::Parser;

/// DNS brute-force enumeration tool for discovering internal assets.
#[derive(Parser, Debug)]
#[command(name = "dnsbrute", version, about)]
pub struct Args {
    /// Base domain to enumerate (required)
    #[arg(short, long)]
    pub domain: String,

    /// Maximum length of subdomain combinations (max 63, DNS label limit)
    #[arg(short, long, default_value_t = 5)]
    pub maxlen: usize,

    /// Number of concurrent workers
    #[arg(short, long, default_value_t = default_workers())]
    pub workers: usize,

    /// Timeout per DNS query
    #[arg(short, long, default_value = "2s", value_parser = parse_duration)]
    pub timeout: Duration,

    /// Enable wildcard detection
    #[arg(
        short = 'W',
        long,
        action = clap::ArgAction::Set,
        num_args = 0..=1,
        default_missing_value = "true",
        default_value = "true"
    )]
    pub wildcard: bool,

    /// Output file for results (default: stdout)
    #[arg(short, long)]
    pub out: Option<String>,

    /// Maximum number of combinations to generate (0 = unlimited)
    #[arg(short = 'c', long, default_value_t = 0)]
    pub max_combinations: u64,

    /// Channel buffer size for job dispatching
    #[arg(short, long, default_value_t = 100)]
    pub buffer: usize,

    /// Checkpoint file for resumable enumeration
    #[arg(short = 'k', long)]
    pub checkpoint: Option<String>,

    /// Negative DNS cache TTL (0 = disabled)
    #[arg(short = 'l', long, default_value = "5m", value_parser = parse_duration)]
    pub cache_ttl: Duration,
}

/// Parses durations like `2s`, `5m`, `1h` (seconds/minutes/hours).
fn parse_duration(s: &str) -> Result<Duration, String> {
    let (num, unit) = s.split_at(s.len().saturating_sub(1));
    let n: u64 = num.parse().map_err(|_| format!("invalid duration: {s}"))?;
    let secs = match unit {
        "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        _ => return Err(format!("invalid duration unit: {s} (use s, m, h)")),
    };
    Ok(Duration::from_secs(secs))
}

fn default_workers() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

impl Args {
    /// Validates flags, capping maxlen at the DNS label limit.
    pub fn validate(&mut self) -> Result<(), String> {
        if self.domain.is_empty() {
            return Err("--domain is required".into());
        }
        if self.maxlen < 1 {
            return Err("--maxlen must be >= 1".into());
        }
        if self.maxlen > 63 {
            self.maxlen = 63;
        }
        if self.workers < 1 {
            return Err("--workers must be >= 1".into());
        }
        if self.buffer < 1 {
            return Err("--buffer must be >= 1".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Args {
        Args::try_parse_from(args).expect("args should parse")
    }

    #[test]
    fn parses_all_flags() {
        let a = parse(&[
            "dnsbrute",
            "-d",
            "example.com",
            "-m",
            "3",
            "-w",
            "10",
            "-t",
            "1s",
            "-W",
            "-o",
            "out.txt",
            "-c",
            "500",
            "-b",
            "50",
            "-k",
            "cp.json",
            "-l",
            "10m",
        ]);
        assert_eq!(a.domain, "example.com");
        assert_eq!(a.maxlen, 3);
        assert_eq!(a.workers, 10);
        assert_eq!(a.timeout, Duration::from_secs(1));
        assert!(a.wildcard);
        assert_eq!(a.out.as_deref(), Some("out.txt"));
        assert_eq!(a.max_combinations, 500);
        assert_eq!(a.buffer, 50);
        assert_eq!(a.checkpoint.as_deref(), Some("cp.json"));
        assert_eq!(a.cache_ttl, Duration::from_secs(600));
    }

    #[test]
    fn wildcard_defaults_to_true() {
        let a = parse(&["dnsbrute", "-d", "example.com"]);
        assert!(a.wildcard);
    }

    #[test]
    fn wildcard_can_be_disabled() {
        let a = parse(&["dnsbrute", "-d", "example.com", "--wildcard=false"]);
        assert!(!a.wildcard);
    }

    #[test]
    fn validate_rejects_missing_domain() {
        // clap itself rejects a missing required --domain at parse time.
        assert!(Args::try_parse_from(["dnsbrute"]).is_err());
    }

    #[test]
    fn validate_rejects_zero_workers() {
        let mut a = parse(&["dnsbrute", "-d", "example.com", "-w", "0"]);
        assert_eq!(a.validate(), Err("--workers must be >= 1".into()));
    }

    #[test]
    fn validate_rejects_zero_buffer() {
        let mut a = parse(&["dnsbrute", "-d", "example.com", "-b", "0"]);
        assert_eq!(a.validate(), Err("--buffer must be >= 1".into()));
    }

    #[test]
    fn validate_caps_maxlen_at_63() {
        let mut a = parse(&["dnsbrute", "-d", "example.com", "-m", "100"]);
        a.validate().unwrap();
        assert_eq!(a.maxlen, 63);
    }
}
