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
}
