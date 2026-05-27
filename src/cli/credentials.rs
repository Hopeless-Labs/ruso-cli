//! On-disk token storage for `ruso login`.
//!
//! Layout: a plain-text JSON file at `$XDG_CONFIG_HOME/ruso/credentials.json`
//! (Linux/macOS) or `%APPDATA%\ruso\credentials.json` (Windows). Mode 0600
//! on Unix. One file per registry — keyed by `base_url` — so the same
//! machine can be logged into local + hosted at the same time.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CredentialError {
    #[error("could not determine config directory")]
    NoConfigDir,
    #[error("failed to read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to write {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse {path}: {source}")]
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("not logged in to {registry} (run `ruso login --token …`)")]
    NotLoggedIn { registry: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub token: String,
    /// Mirror of the user the token belonged to at login time. Display-only —
    /// authoritative source is always `/v1/me`.
    pub username: Option<String>,
}

/// On-disk shape. Indexed by registry base URL so the same file can hold
/// credentials for the local backend and a future hosted one.
#[derive(Debug, Default, Serialize, Deserialize)]
struct CredentialsFile {
    #[serde(default)]
    registries: HashMap<String, Credentials>,
}

pub fn credentials_path() -> Result<PathBuf, CredentialError> {
    let dir = dirs::config_dir().ok_or(CredentialError::NoConfigDir)?;
    Ok(dir.join("ruso").join("credentials.json"))
}

pub fn load(registry: &str) -> Result<Option<Credentials>, CredentialError> {
    let path = credentials_path()?;
    let file = read_file(&path)?;
    Ok(file.registries.get(registry).cloned())
}

pub fn require(registry: &str) -> Result<Credentials, CredentialError> {
    load(registry)?.ok_or_else(|| CredentialError::NotLoggedIn {
        registry: registry.to_string(),
    })
}

pub fn save(registry: &str, creds: Credentials) -> Result<PathBuf, CredentialError> {
    let path = credentials_path()?;
    let mut file = read_file(&path)?;
    file.registries.insert(registry.to_string(), creds);
    write_file(&path, &file)?;
    Ok(path)
}

pub fn delete(registry: &str) -> Result<bool, CredentialError> {
    let path = credentials_path()?;
    let mut file = read_file(&path)?;
    let removed = file.registries.remove(registry).is_some();
    if removed {
        write_file(&path, &file)?;
    }
    Ok(removed)
}

fn read_file(path: &PathBuf) -> Result<CredentialsFile, CredentialError> {
    match fs::read(path) {
        Ok(bytes) if bytes.is_empty() => Ok(CredentialsFile::default()),
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|source| CredentialError::Parse {
            path: path.clone(),
            source,
        }),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(CredentialsFile::default()),
        Err(source) => Err(CredentialError::Read {
            path: path.clone(),
            source,
        }),
    }
}

fn write_file(path: &PathBuf, file: &CredentialsFile) -> Result<(), CredentialError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| CredentialError::Write {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    // Write to a tmp file in the same directory then atomically rename, so a
    // crash mid-write can't leave a half-written credentials file behind.
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(file).map_err(|source| CredentialError::Parse {
        path: path.clone(),
        source,
    })?;
    fs::write(&tmp, &bytes).map_err(|source| CredentialError::Write {
        path: tmp.clone(),
        source,
    })?;
    set_secret_mode(&tmp)?;
    fs::rename(&tmp, path).map_err(|source| CredentialError::Write {
        path: path.clone(),
        source,
    })?;
    Ok(())
}

#[cfg(unix)]
fn set_secret_mode(path: &PathBuf) -> Result<(), CredentialError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    fs::set_permissions(path, perms).map_err(|source| CredentialError::Write {
        path: path.clone(),
        source,
    })
}

#[cfg(not(unix))]
fn set_secret_mode(_path: &PathBuf) -> Result<(), CredentialError> {
    // Windows file ACLs don't have a direct chmod analogue and the default
    // ACL on `%APPDATA%` is already user-private. No-op.
    Ok(())
}
