//! Discover `.ruso` scripts and `.bc` bytecode files from a path.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DiscoverError {
    #[error("path not found: {0}")]
    NotFound(PathBuf),
    #[error("not a .ruso script file: {0}")]
    NotScript(PathBuf),
    #[error("not a .bc bytecode file: {0}")]
    NotBytecode(PathBuf),
    #[error("no .ruso scripts found under {0}")]
    EmptyScripts(PathBuf),
    #[error("no .bc bytecode files found under {0}")]
    EmptyBytecode(PathBuf),
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
        let mut visited = HashSet::new();
        collect_by_extension(path, "ruso", &mut scripts, &mut visited)?;
        if scripts.is_empty() {
            return Err(DiscoverError::EmptyScripts(path.to_path_buf()));
        }
        scripts.sort();
        return Ok(scripts);
    }

    Err(DiscoverError::NotFound(path.to_path_buf()))
}

/// Resolve a bytecode path to one or more `.bc` files.
///
/// - File: must have extension `bc`
/// - Directory: all `*.bc` files under it, recursively
pub fn discover_bytecode(path: &Path) -> Result<Vec<PathBuf>, DiscoverError> {
    if !path.exists() {
        return Err(DiscoverError::NotFound(path.to_path_buf()));
    }

    if path.is_file() {
        if path.extension().is_some_and(|ext| ext == "bc") {
            return Ok(vec![path.to_path_buf()]);
        }
        return Err(DiscoverError::NotBytecode(path.to_path_buf()));
    }

    if path.is_dir() {
        let mut files = Vec::new();
        let mut visited = HashSet::new();
        collect_by_extension(path, "bc", &mut files, &mut visited)?;
        if files.is_empty() {
            return Err(DiscoverError::EmptyBytecode(path.to_path_buf()));
        }
        files.sort();
        return Ok(files);
    }

    Err(DiscoverError::NotFound(path.to_path_buf()))
}

/// `checks/foo.ruso` → `checks/foo.bc` (same parent, `.bc` extension).
pub fn bytecode_path_for_script(script: &Path) -> PathBuf {
    script.with_extension("bc")
}

fn collect_by_extension(
    dir: &Path,
    extension: &str,
    out: &mut Vec<PathBuf>,
    visited: &mut HashSet<PathBuf>,
) -> Result<(), DiscoverError> {
    // Canonicalise to follow symlinks and cycle-detect — without this a
    // symlink loop (`a -> b`, `b -> a`) would recurse until the stack
    // overflowed.
    let canonical = std::fs::canonicalize(dir).map_err(|source| DiscoverError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    if !visited.insert(canonical) {
        return Ok(());
    }

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
            collect_by_extension(&path, extension, out, visited)?;
        } else if path.extension().is_some_and(|ext| ext == extension) {
            out.push(path);
        }
    }

    Ok(())
}
