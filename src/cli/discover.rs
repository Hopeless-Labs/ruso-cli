//! Discover `.ruso` scripts from a file or directory path.

use std::path::{Path, PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DiscoverError {
    #[error("script path not found: {0}")]
    NotFound(PathBuf),
    #[error("not a .ruso script file: {0}")]
    NotScript(PathBuf),
    #[error("no .ruso scripts found under {0}")]
    Empty(PathBuf),
    #[error("failed to read {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

/// Resolve a script path to one or more `.ruso` files.
///
/// - File: must have extension `ruso`
/// - Directory: all `*.ruso` files under it, recursively
pub fn discover_scripts(path: &Path) -> Result<Vec<PathBuf>, DiscoverError> {
    if !path.exists() {
        return Err(DiscoverError::NotFound(path.to_path_buf()));
    }

    if path.is_file() {
        if path.extension().is_some_and(|ext| ext == "ruso") {
            return Ok(vec![path.to_path_buf()]);
        }
        return Err(DiscoverError::NotScript(path.to_path_buf()));
    }

    if path.is_dir() {
        let mut scripts = Vec::new();
        collect_scripts_recursive(path, &mut scripts)?;
        if scripts.is_empty() {
            return Err(DiscoverError::Empty(path.to_path_buf()));
        }
        scripts.sort();
        return Ok(scripts);
    }

    Err(DiscoverError::NotFound(path.to_path_buf()))
}

fn collect_scripts_recursive(dir: &Path, scripts: &mut Vec<PathBuf>) -> Result<(), DiscoverError> {
    let read_dir = std::fs::read_dir(dir).map_err(|source| DiscoverError::Io {
        path: dir.to_path_buf(),
        source,
    })?;

    for entry in read_dir {
        let entry = entry.map_err(|source| DiscoverError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|source| DiscoverError::Io {
            path: path.clone(),
            source,
        })?;

        if file_type.is_dir() {
            collect_scripts_recursive(&path, scripts)?;
        } else if path.extension().is_some_and(|ext| ext == "ruso") {
            scripts.push(path);
        }
    }

    Ok(())
}
