use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

/// Persistent checkpoint state, JSON-compatible with the Go version's schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointData {
    pub completed: u64,
    pub last_index: Vec<usize>,
    pub length: usize,
    pub timestamp: String,
    pub max_len: usize,
    pub domain: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wildcard_ips: Vec<String>,
}

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Loads checkpoint data, rejecting it when domain or max_len mismatch.
pub fn load(
    path: &Path,
    expected_domain: &str,
    expected_max_len: usize,
) -> Result<CheckpointData, String> {
    let content = fs::read_to_string(path).map_err(|e| format!("read checkpoint: {e}"))?;
    let cp: CheckpointData =
        serde_json::from_str(&content).map_err(|e| format!("parse checkpoint: {e}"))?;
    if cp.domain != expected_domain {
        return Err(format!(
            "checkpoint domain mismatch: {} != {}",
            cp.domain, expected_domain
        ));
    }
    if cp.max_len != expected_max_len {
        return Err(format!(
            "checkpoint max_len mismatch: {} != {}",
            cp.max_len, expected_max_len
        ));
    }
    Ok(cp)
}

/// Saves checkpoint data atomically (temp file + rename + sync, mode 0600).
pub fn save(path: &Path, data: &CheckpointData) -> Result<(), String> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let tmp_path = dir.join(format!(
        ".checkpoint-{}-{}.tmp",
        std::process::id(),
        TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));

    let json = serde_json::to_string(data).map_err(|e| format!("encode checkpoint: {e}"))?;
    {
        let mut f = fs::File::create(&tmp_path).map_err(|e| format!("create temp file: {e}"))?;
        f.write_all(json.as_bytes())
            .map_err(|e| format!("write temp file: {e}"))?;
        f.sync_all().map_err(|e| format!("sync: {e}"))?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("set permissions: {e}"))?;
    }

    fs::rename(&tmp_path, path).map_err(|e| format!("atomic rename: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("dnsbrute-test-{}-{name}", std::process::id()))
    }

    fn sample() -> CheckpointData {
        CheckpointData {
            completed: 42,
            last_index: vec![1, 5, 3],
            length: 3,
            timestamp: "2026-08-18T00:00:00Z".into(),
            max_len: 3,
            domain: "example.com".into(),
            wildcard_ips: vec!["10.0.0.1".into()],
        }
    }

    #[test]
    fn round_trip_save_load() {
        let path = tmp_path("roundtrip.json");
        let data = sample();
        save(&path, &data).unwrap();
        let loaded = load(&path, "example.com", 3).unwrap();
        assert_eq!(loaded.completed, 42);
        assert_eq!(loaded.last_index, vec![1, 5, 3]);
        assert_eq!(loaded.length, 3);
        assert_eq!(loaded.domain, "example.com");
        assert_eq!(loaded.wildcard_ips, vec!["10.0.0.1"]);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn rejects_domain_mismatch() {
        let path = tmp_path("domain-mismatch.json");
        save(&path, &sample()).unwrap();
        let err = load(&path, "other.com", 3).unwrap_err();
        assert!(err.contains("domain mismatch"));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn rejects_maxlen_mismatch() {
        let path = tmp_path("maxlen-mismatch.json");
        save(&path, &sample()).unwrap();
        let err = load(&path, "example.com", 5).unwrap_err();
        assert!(err.contains("max_len mismatch"));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn writes_compact_json_with_0600_perms() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = tmp_path("perms.json");
            save(&path, &sample()).unwrap();
            let content = fs::read_to_string(&path).unwrap();
            assert!(!content.contains('\n'), "expected compact JSON");
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
            let _ = fs::remove_file(&path);
        }
    }
}
