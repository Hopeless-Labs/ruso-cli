//! Local install cache + registry-ref resolution.
//!
//! Layout: `<home>/.ruso/scripts/<namespace>/<name>/<version>.bc`
//!
//! `RegistryRef` is the parsed `<namespace>/<name>[@<range>]` form a user
//! types in `--script`. `resolve` walks installed versions, picks the best
//! match per range, and falls back to a registry fetch+install when nothing
//! local satisfies it.

use std::fs;
use std::path::PathBuf;

use semver::{Version, VersionReq};
use thiserror::Error;

use crate::cli::registry::{RegistryClient, RegistryError};

#[derive(Debug, Error)]
pub enum InstallError {
    #[error("could not determine home directory")]
    NoHomeDir,
    #[error("invalid SemVer range `{range}`: {source}")]
    BadRange {
        range: String,
        source: semver::Error,
    },
    #[error("no versions of {namespace}/{name} match {range}")]
    NoMatchingVersion {
        namespace: String,
        name: String,
        range: String,
    },
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
    #[error(transparent)]
    Registry(#[from] RegistryError),
}

/// Parsed `<ns>/<name>[@<range>]` reference. `range` of `None` means "any
/// non-yanked version, newest wins."
#[derive(Debug, Clone)]
pub struct RegistryRef {
    pub namespace: String,
    pub name: String,
    pub range: Option<String>,
}

impl RegistryRef {
    pub fn display(&self) -> String {
        match &self.range {
            Some(r) => format!("{}/{}@{}", self.namespace, self.name, r),
            None => format!("{}/{}", self.namespace, self.name),
        }
    }
}

/// Best-effort parse. Returns `None` for anything that doesn't match the
/// shape — caller treats those as filesystem paths.
pub fn parse_ref(input: &str) -> Option<RegistryRef> {
    // Reject anything that obviously names a filesystem path so a relative
    // path like `checks/foo` (which matches the slug shape!) isn't ever
    // misread as a registry ref. Final disambiguation still happens at the
    // discover layer (filesystem existence wins).
    if input.starts_with('.') || input.starts_with('/') || input.starts_with('~') {
        return None;
    }
    if input.contains('\\') || input.contains(' ') {
        return None;
    }
    let (head, range) = match input.split_once('@') {
        Some((h, r)) if !r.is_empty() => (h, Some(r.to_string())),
        Some(_) => return None, // trailing `@` with empty range
        None => (input, None),
    };
    let (ns, name) = head.split_once('/')?;
    if !is_slug(ns) || !is_slug(name) {
        return None;
    }
    Some(RegistryRef {
        namespace: ns.to_string(),
        name: name.to_string(),
        range,
    })
}

fn is_slug(s: &str) -> bool {
    // Matches the backend's slug rule: lowercase alphanumeric + hyphen,
    // can't start with hyphen, len 1..=39 (mirrors GitHub login limit).
    if s.is_empty() || s.len() > 39 {
        return false;
    }
    let bytes = s.as_bytes();
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

#[derive(Debug, Clone)]
pub struct InstallStore {
    root: PathBuf,
}

impl InstallStore {
    /// Default location: `$HOME/.ruso`. Override via `RUSO_HOME` env so
    /// CI / tests can pin a temp dir.
    pub fn default_for_user() -> Result<Self, InstallError> {
        if let Ok(custom) = std::env::var("RUSO_HOME")
            && !custom.is_empty()
        {
            return Ok(Self {
                root: PathBuf::from(custom),
            });
        }
        let home = dirs::home_dir().ok_or(InstallError::NoHomeDir)?;
        Ok(Self {
            root: home.join(".ruso"),
        })
    }

    pub fn script_dir(&self, namespace: &str, name: &str) -> PathBuf {
        self.root.join("scripts").join(namespace).join(name)
    }

    pub fn bytecode_path(&self, namespace: &str, name: &str, version: &str) -> PathBuf {
        self.script_dir(namespace, name)
            .join(format!("{version}.bc"))
    }

    /// All installed versions of `<ns>/<name>` in semver order (newest first).
    /// Silently skips files with names that don't parse as SemVer.
    pub fn list_installed(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Vec<Version>, InstallError> {
        let dir = self.script_dir(namespace, name);
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut versions = Vec::new();
        let read_dir = fs::read_dir(&dir).map_err(|source| InstallError::Read {
            path: dir.clone(),
            source,
        })?;
        for entry in read_dir {
            let entry = entry.map_err(|source| InstallError::Read {
                path: dir.clone(),
                source,
            })?;
            let path = entry.path();
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            if path.extension().and_then(|e| e.to_str()) != Some("bc") {
                continue;
            }
            if let Ok(v) = Version::parse(stem) {
                versions.push(v);
            }
        }
        versions.sort_by(|a, b| b.cmp(a));
        Ok(versions)
    }

    /// Write a downloaded bytecode blob into the cache. Returns the path.
    pub fn write_bytecode(
        &self,
        namespace: &str,
        name: &str,
        version: &str,
        bytes: &[u8],
    ) -> Result<PathBuf, InstallError> {
        let dir = self.script_dir(namespace, name);
        fs::create_dir_all(&dir).map_err(|source| InstallError::Write {
            path: dir.clone(),
            source,
        })?;
        let path = dir.join(format!("{version}.bc"));
        fs::write(&path, bytes).map_err(|source| InstallError::Write {
            path: path.clone(),
            source,
        })?;
        Ok(path)
    }
}

/// Pick the best locally-installed version that matches `range` (or the
/// newest, if `range` is None). Returns `None` if nothing matches.
pub fn best_local_match(
    store: &InstallStore,
    namespace: &str,
    name: &str,
    range: Option<&str>,
) -> Result<Option<Version>, InstallError> {
    let installed = store.list_installed(namespace, name)?;
    let req = parse_range(range)?;
    Ok(pick_match(&installed, req.as_ref()))
}

fn pick_match(installed: &[Version], req: Option<&VersionReq>) -> Option<Version> {
    // `installed` is newest-first, so the first match wins.
    installed
        .iter()
        .find(|v| match req {
            Some(r) => r.matches(v),
            None => true,
        })
        .cloned()
}

fn parse_range(range: Option<&str>) -> Result<Option<VersionReq>, InstallError> {
    let Some(r) = range else { return Ok(None) };
    VersionReq::parse(r)
        .map(Some)
        .map_err(|source| InstallError::BadRange {
            range: r.to_string(),
            source,
        })
}

/// One-shot install: ask the registry for the script's versions, pick the
/// best non-yanked match for `range`, download the bytecode, write it to
/// the cache. Returns `(version, path)`. If a matching version is already
/// installed, returns the cached path without hitting the network.
pub async fn install(
    store: &InstallStore,
    client: &RegistryClient,
    r#ref: &RegistryRef,
) -> Result<(Version, PathBuf), InstallError> {
    if let Some(local) =
        best_local_match(store, &r#ref.namespace, &r#ref.name, r#ref.range.as_deref())?
    {
        let path = store.bytecode_path(&r#ref.namespace, &r#ref.name, &local.to_string());
        if path.exists() {
            return Ok((local, path));
        }
    }

    let req = parse_range(r#ref.range.as_deref())?;
    let script = client
        .show(&r#ref.namespace, &r#ref.name, r#ref.range.as_deref())
        .await?;

    // Even with `?range=`, the backend may include yanked versions outside
    // the filter — re-check locally so the CLI never installs a yanked rev.
    let mut candidates: Vec<Version> = script
        .versions
        .iter()
        .filter(|v| v.yanked_at.is_none())
        .filter_map(|v| Version::parse(&v.version).ok())
        .collect();
    candidates.sort_by(|a, b| b.cmp(a));

    let pick =
        pick_match(&candidates, req.as_ref()).ok_or_else(|| InstallError::NoMatchingVersion {
            namespace: r#ref.namespace.clone(),
            name: r#ref.name.clone(),
            range: r#ref.range.clone().unwrap_or_else(|| "*".to_string()),
        })?;

    let bytes = client
        .download_bytecode(&r#ref.namespace, &r#ref.name, &pick.to_string())
        .await?;
    let path = store.write_bytecode(&r#ref.namespace, &r#ref.name, &pick.to_string(), &bytes)?;
    Ok((pick, path))
}

/// Resolve a `RegistryRef` to a local path, fetching from the registry on
/// cache miss. Used by `--script ns/name[@range]` in scan/exec.
pub async fn resolve_to_path(
    store: &InstallStore,
    client: &RegistryClient,
    r#ref: &RegistryRef,
) -> Result<PathBuf, InstallError> {
    install(store, client, r#ref).await.map(|(_, p)| p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ref_basic() {
        let r = parse_ref("alice/log4shell").unwrap();
        assert_eq!(r.namespace, "alice");
        assert_eq!(r.name, "log4shell");
        assert!(r.range.is_none());
    }

    #[test]
    fn parse_ref_with_range() {
        let r = parse_ref("alice/log4shell@^1.2").unwrap();
        assert_eq!(r.range.as_deref(), Some("^1.2"));
    }

    #[test]
    fn parse_ref_rejects_paths() {
        assert!(parse_ref("./foo/bar").is_none());
        assert!(parse_ref("/abs/foo/bar").is_none());
        assert!(parse_ref("~/foo/bar").is_none());
        assert!(parse_ref("foo/bar/baz").is_none()); // three segments
        assert!(parse_ref("Foo/bar").is_none()); // uppercase
        assert!(parse_ref("foo/bar@").is_none()); // empty range
    }

    #[test]
    fn pick_match_newest_first() {
        let installed = vec![
            Version::parse("2.0.0").unwrap(),
            Version::parse("1.2.1").unwrap(),
            Version::parse("1.1.0").unwrap(),
        ];
        let req = VersionReq::parse("^1").unwrap();
        let got = pick_match(&installed, Some(&req)).unwrap();
        assert_eq!(got.to_string(), "1.2.1");
    }
}
