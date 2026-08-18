/// Alphabet of subdomain characters, in lexicographic order.
pub const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789-";

/// DNS label maximum length.
pub const MAX_MAX_LEN: usize = 63;

/// Iteratively produces subdomain combinations of length 1..=max_len.
pub struct Generator {
    indices: Vec<usize>,
    length: usize,
    max_len: usize,
    max_combs: Option<u64>,
    produced: u64,
}

impl Generator {
    /// Creates a generator starting from the first combination.
    pub fn new(max_len: usize, max_combs: u64) -> Self {
        let max_len = max_len.min(MAX_MAX_LEN);
        Self {
            indices: vec![0; max_len],
            length: 1,
            max_len,
            max_combs: (max_combs > 0).then_some(max_combs),
            produced: 0,
        }
    }

    /// Creates a generator resuming from a checkpoint position.
    pub fn resume(
        max_len: usize,
        max_combs: u64,
        last_index: Vec<usize>,
        length: usize,
        completed: u64,
    ) -> Self {
        let max_len = max_len.min(MAX_MAX_LEN);
        let mut indices = vec![0; max_len];
        let n = last_index.len().min(max_len);
        indices[..n].copy_from_slice(&last_index[..n]);
        // A saved length past max_len means the generator was exhausted;
        // keep it so `next()` returns None instead of restarting.
        let length = length.max(1);
        Self {
            indices,
            length,
            max_len,
            max_combs: (max_combs > 0).then_some(max_combs),
            produced: completed,
        }
    }

    /// Returns the next combination, or `None` when exhausted or the
    /// combination limit is reached.
    pub fn next(&mut self) -> Option<String> {
        if self.length > self.max_len {
            return None;
        }
        if let Some(max) = self.max_combs {
            if self.produced >= max {
                return None;
            }
        }
        let mut s = String::with_capacity(self.length);
        for i in 0..self.length {
            s.push(ALPHABET[self.indices[i]] as char);
        }
        self.produced += 1;
        self.advance();
        Some(s)
    }

    /// Advances the odometer to the next combination.
    fn advance(&mut self) {
        for i in (0..self.length).rev() {
            self.indices[i] += 1;
            if self.indices[i] < ALPHABET.len() {
                return;
            }
            self.indices[i] = 0;
            if i == 0 {
                self.length += 1;
                return;
            }
        }
    }

    /// Snapshot of the generator state for checkpointing.
    pub fn state(&self) -> (Vec<usize>, usize, u64) {
        (self.indices.clone(), self.length, self.produced)
    }

    /// Total number of combinations in the full space (1..=max_len).
    pub fn total(&self) -> u64 {
        let mut total = 0u64;
        for len in 1..=self.max_len {
            total += (ALPHABET.len() as u64).pow(len as u32);
        }
        total
    }
}

/// Iteratively produces subdomain names from a wordlist file (one per line).
pub struct WordlistGenerator {
    lines: Vec<String>,
    index: usize,
    max_combs: Option<u64>,
    produced: u64,
}

impl WordlistGenerator {
    /// Loads a wordlist, skipping blank lines and `#` comments.
    pub fn new(path: &str, max_combs: u64) -> Result<Self, String> {
        let content =
            std::fs::read_to_string(path).map_err(|e| format!("read wordlist {path}: {e}"))?;
        let lines: Vec<String> = content
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(String::from)
            .collect();
        if lines.is_empty() {
            return Err(format!("wordlist {path} has no entries"));
        }
        Ok(Self {
            lines,
            index: 0,
            max_combs: (max_combs > 0).then_some(max_combs),
            produced: 0,
        })
    }

    /// Creates a generator resuming from a checkpoint line index.
    pub fn resume(
        path: &str,
        max_combs: u64,
        index: usize,
        completed: u64,
    ) -> Result<Self, String> {
        let mut g = Self::new(path, max_combs)?;
        g.index = index.min(g.lines.len());
        g.produced = completed;
        Ok(g)
    }

    /// Returns the next wordlist entry, or `None` when exhausted.
    pub fn next(&mut self) -> Option<String> {
        if self.index >= self.lines.len() {
            return None;
        }
        if let Some(max) = self.max_combs {
            if self.produced >= max {
                return None;
            }
        }
        let s = self.lines[self.index].clone();
        self.index += 1;
        self.produced += 1;
        Some(s)
    }

    /// Snapshot of the generator state for checkpointing (index as `vec![i]`).
    pub fn state(&self) -> (Vec<usize>, usize, u64) {
        (vec![self.index], 1, self.produced)
    }

    /// Total number of entries in the wordlist.
    pub fn total(&self) -> u64 {
        self.lines.len() as u64
    }
}

/// Job source for the pipeline: exhaustive brute-force or wordlist.
pub enum JobSource {
    Brute(Generator),
    Wordlist(WordlistGenerator),
}

impl JobSource {
    /// Returns the next job, or `None` when exhausted.
    pub fn next(&mut self) -> Option<String> {
        match self {
            JobSource::Brute(g) => g.next(),
            JobSource::Wordlist(g) => g.next(),
        }
    }

    /// Snapshot of the generator state for checkpointing.
    pub fn state(&self) -> (Vec<usize>, usize, u64) {
        match self {
            JobSource::Brute(g) => g.state(),
            JobSource::Wordlist(g) => g.state(),
        }
    }

    /// Total number of jobs in the full space (for progress reporting).
    pub fn total(&self) -> u64 {
        match self {
            JobSource::Brute(g) => g.total(),
            JobSource::Wordlist(g) => g.total(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_all_single_char_combinations() {
        let mut g = Generator::new(1, 0);
        let mut count = 0;
        while let Some(c) = g.next() {
            assert_eq!(c.len(), 1);
            assert!(ALPHABET.contains(&c.as_bytes()[0]));
            count += 1;
        }
        assert_eq!(count, ALPHABET.len());
    }

    #[test]
    fn progresses_to_next_length() {
        let mut g = Generator::new(2, 0);
        let mut count = 0;
        let mut saw_two = false;
        while let Some(c) = g.next() {
            if c.len() == 2 {
                saw_two = true;
            }
            count += 1;
        }
        assert!(saw_two);
        assert_eq!(count, ALPHABET.len() + ALPHABET.len() * ALPHABET.len());
    }

    #[test]
    fn caps_max_len_at_63() {
        let g = Generator::new(100, 0);
        assert_eq!(g.max_len, 63);
    }

    #[test]
    fn respects_max_combs() {
        let mut g = Generator::new(3, 5);
        let mut count = 0;
        while g.next().is_some() {
            count += 1;
        }
        assert_eq!(count, 5);
    }

    #[test]
    fn resumes_without_repetition() {
        let mut g = Generator::new(2, 0);
        let mut first: Vec<String> = Vec::new();
        for _ in 0..50 {
            first.push(g.next().unwrap());
        }
        let (last_index, length, produced) = g.state();
        assert_eq!(produced, 50);

        let mut resumed = Generator::resume(2, 0, last_index, length, produced);
        let mut rest: Vec<String> = Vec::new();
        while let Some(c) = resumed.next() {
            rest.push(c);
        }

        // No overlap between first 50 and the rest.
        let first_set: std::collections::HashSet<_> = first.iter().collect();
        assert!(rest.iter().all(|c| !first_set.contains(c)));
        // Total is the full space.
        assert_eq!(
            first.len() + rest.len(),
            ALPHABET.len() + ALPHABET.len() * ALPHABET.len()
        );
    }

    #[test]
    fn resume_from_exhausted_state_produces_nothing() {
        // length past max_len means the generator finished.
        let mut g = Generator::resume(1, 0, vec![0], 2, 37);
        assert!(g.next().is_none());
    }

    #[test]
    fn total_counts_full_space() {
        let g = Generator::new(2, 0);
        assert_eq!(g.total(), 37 + 37 * 37);
    }

    #[test]
    fn wordlist_iterates_lines_and_skips_comments() {
        let path = std::env::temp_dir().join(format!("dnsbrute-wl-{}.txt", std::process::id()));
        std::fs::write(&path, "admin\n# comment\n\nwww\napi\n").unwrap();
        let mut g = WordlistGenerator::new(path.to_str().unwrap(), 0).unwrap();
        assert_eq!(g.total(), 3);
        assert_eq!(g.next().as_deref(), Some("admin"));
        assert_eq!(g.next().as_deref(), Some("www"));
        assert_eq!(g.next().as_deref(), Some("api"));
        assert!(g.next().is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn wordlist_resumes_from_index() {
        let path = std::env::temp_dir().join(format!("dnsbrute-wl2-{}.txt", std::process::id()));
        std::fs::write(&path, "a\nb\nc\nd\n").unwrap();
        let mut g = WordlistGenerator::resume(path.to_str().unwrap(), 0, 2, 2).unwrap();
        assert_eq!(g.next().as_deref(), Some("c"));
        assert_eq!(g.next().as_deref(), Some("d"));
        assert!(g.next().is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn wordlist_rejects_empty_file() {
        let path = std::env::temp_dir().join(format!("dnsbrute-wl3-{}.txt", std::process::id()));
        std::fs::write(&path, "# only comments\n").unwrap();
        assert!(WordlistGenerator::new(path.to_str().unwrap(), 0).is_err());
        let _ = std::fs::remove_file(&path);
    }
}
