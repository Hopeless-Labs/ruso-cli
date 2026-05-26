//! Resolve `--target` to one or more scan origins (URL or targets file).

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TargetError {
    #[error("target path not found: {0}")]
    NotFound(PathBuf),
    #[error("targets file is empty: {0}")]
    EmptyFile(PathBuf),
    #[error("no valid targets in file: {0}")]
    NoValidTargets(PathBuf),
    #[error("invalid target (expected URL or path to targets file): {0}")]
    Invalid(String),
    #[error("failed to read {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

/// Resolve `--target` to a list of base URLs.
///
/// - Existing **file**: one URL per line (`#` comments and blank lines ignored)
/// - **URL** (`http://` / `https://`): single target
pub fn discover_targets(target: &str) -> Result<Vec<String>, TargetError> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return Err(TargetError::Invalid(target.to_string()));
    }

    let path = Path::new(trimmed);
    if path.is_file() {
        return read_targets_file(path);
    }

    if is_url(trimmed) {
        return Ok(vec![trimmed.to_string()]);
    }

    if path.exists() {
        return Err(TargetError::NotFound(path.to_path_buf()));
    }

    Err(TargetError::Invalid(trimmed.to_string()))
}

fn read_targets_file(path: &Path) -> Result<Vec<String>, TargetError> {
    let file = std::fs::File::open(path).map_err(|source| TargetError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let reader = BufReader::new(file);

    let mut targets = Vec::new();
    for line in reader.lines() {
        let line = line.map_err(|source| TargetError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        if let Some(url) = parse_target_line(&line) {
            targets.push(url);
        }
    }

    if targets.is_empty() {
        let bytes = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        if bytes == 0 {
            return Err(TargetError::EmptyFile(path.to_path_buf()));
        }
        return Err(TargetError::NoValidTargets(path.to_path_buf()));
    }

    Ok(targets)
}

fn parse_target_line(line: &str) -> Option<String> {
    // Only treat `#` as a comment when it starts the line — splitting on
    // `#` everywhere would mangle URLs like `https://app/route#section`,
    // dropping the fragment that some SPAs route off of.
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    if is_url(trimmed) {
        Some(trimmed.to_string())
    } else {
        None
    }
}

fn is_url(value: &str) -> bool {
    let value = value.trim();
    let rest = if let Some(rest) = value.strip_prefix("http://") {
        rest
    } else if let Some(rest) = value.strip_prefix("https://") {
        rest
    } else {
        return false;
    };
    // Reject "http://" with no authority — the bare scheme is not a usable
    // target and would otherwise pass the original startswith-only check.
    !rest.is_empty() && !rest.starts_with('/')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn discovers_single_url() {
        assert_eq!(
            discover_targets("https://example.com").unwrap(),
            vec!["https://example.com".to_string()]
        );
    }

    #[test]
    fn reads_targets_file() {
        let dir = std::env::temp_dir().join("ruso_targets_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("targets.txt");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "# lab").unwrap();
        writeln!(f, "http://127.0.0.1:19080").unwrap();
        writeln!(f, "https://example.com").unwrap();
        writeln!(f).unwrap();
        drop(f);

        let urls = discover_targets(path.to_str().unwrap()).unwrap();
        assert_eq!(urls.len(), 2);
        assert_eq!(urls[0], "http://127.0.0.1:19080");
    }

    #[test]
    fn preserves_url_fragment() {
        // Regression for M6: `#section` mid-URL must not be stripped as a
        // comment. SPAs commonly route on the fragment.
        let url = parse_target_line("https://app.example/path#section").unwrap();
        assert_eq!(url, "https://app.example/path#section");
    }

    #[test]
    fn comment_line_with_hash_first_is_ignored() {
        assert!(parse_target_line("# https://example.com").is_none());
        assert!(parse_target_line("   # comment").is_none());
    }

    #[test]
    fn is_url_rejects_bare_scheme() {
        assert!(!is_url("http://"));
        assert!(!is_url("https://"));
        assert!(!is_url("https:///just-a-path"));
    }

    #[test]
    fn is_url_accepts_normal_urls() {
        assert!(is_url("http://example.com"));
        assert!(is_url("https://127.0.0.1:8443"));
        assert!(is_url("http://[::1]:8080"));
    }
}
