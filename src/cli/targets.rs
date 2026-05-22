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
    let line = line.split('#').next()?.trim();
    if line.is_empty() {
        return None;
    }
    if is_url(line) {
        Some(line.to_string())
    } else {
        None
    }
}

fn is_url(value: &str) -> bool {
    let value = value.trim();
    value.starts_with("http://") || value.starts_with("https://")
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
}
