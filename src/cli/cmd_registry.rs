//! Handlers for `ruso login/logout/whoami/publish/install/search` and the
//! shared helpers that wire registry references (`<ns>/<name>[@<range>]`)
//! into `scan` and `exec`.

use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ruso_script::{Program, Stmt, parse};

use crate::cli::args::{
    InstallArgs, LoginArgs, PublishArgs, RegistryArgs, RegistryOnlyArgs, SearchArgs, Visibility,
};
use crate::cli::credentials::{self, Credentials};
use crate::cli::discover::{discover_bytecode, discover_scripts};
use crate::cli::install_store::{self, InstallStore, RegistryRef, parse_ref};
use crate::cli::registry::{RegistryClient, RegistryError, SearchParams, resolve_base_url};
use crate::cli::ui;

// ───────────────────────────── login / logout / whoami ─────────────────────────────

pub async fn cmd_login(args: LoginArgs) -> ExitCode {
    let base_url = resolve_base_url(args.registry.registry.as_deref());

    let token = match args.token {
        Some(t) => t.trim().to_string(),
        None => match read_token_from_stdin() {
            Ok(t) => t,
            Err(err) => {
                ui::error(&err);
                return ExitCode::from(1);
            }
        },
    };
    if token.is_empty() {
        ui::error("empty token");
        return ExitCode::from(1);
    }
    if !(token.starts_with("ruso_pat_") || token.starts_with("ruso_sess_")) {
        ui::error("token must start with `ruso_pat_` or `ruso_sess_`");
        return ExitCode::from(1);
    }

    let client = match RegistryClient::new(base_url.clone(), Some(token.clone())) {
        Ok(c) => c,
        Err(err) => {
            ui::error(&err.to_string());
            return ExitCode::from(1);
        }
    };

    // Probe /v1/me to verify the token before saving — better to fail
    // loudly here than silently store a bad token and fail on the next
    // command.
    let me = match client.me().await {
        Ok(m) => m,
        Err(err) => {
            ui::error(&format!("token rejected by {base_url}: {err}"));
            return ExitCode::from(1);
        }
    };

    let saved_at = match credentials::save(
        &base_url,
        Credentials {
            token,
            username: Some(me.username.clone()),
        },
    ) {
        Ok(p) => p,
        Err(err) => {
            ui::error(&err.to_string());
            return ExitCode::from(1);
        }
    };

    println!(
        "logged in to {base_url} as {} (stored at {})",
        me.username,
        saved_at.display()
    );
    ExitCode::SUCCESS
}

fn read_token_from_stdin() -> Result<String, String> {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        let mut stderr = io::stderr();
        let _ = write!(stderr, "token: ");
        let _ = stderr.flush();
    }
    let mut buf = String::new();
    stdin
        .lock()
        .read_line(&mut buf)
        .map_err(|e| format!("read stdin: {e}"))?;
    Ok(buf.trim().to_string())
}

pub fn cmd_logout(args: RegistryOnlyArgs) -> ExitCode {
    let base_url = resolve_base_url(args.registry.registry.as_deref());
    match credentials::delete(&base_url) {
        Ok(true) => {
            println!("logged out of {base_url}");
            ExitCode::SUCCESS
        }
        Ok(false) => {
            println!("no credential stored for {base_url}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            ui::error(&err.to_string());
            ExitCode::from(1)
        }
    }
}

pub async fn cmd_whoami(args: RegistryOnlyArgs) -> ExitCode {
    let base_url = resolve_base_url(args.registry.registry.as_deref());
    let creds = match credentials::require(&base_url) {
        Ok(c) => c,
        Err(err) => {
            ui::error(&err.to_string());
            return ExitCode::from(1);
        }
    };
    let client = match RegistryClient::new(base_url.clone(), Some(creds.token)) {
        Ok(c) => c,
        Err(err) => {
            ui::error(&err.to_string());
            return ExitCode::from(1);
        }
    };
    match client.me().await {
        Ok(me) => {
            println!("user:     {}", me.username);
            println!("email:    {}", me.email);
            println!("github:   {}", me.github_login);
            println!("admin:    {}", me.is_admin);
            println!("registry: {base_url}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            ui::error(&err.to_string());
            ExitCode::from(1)
        }
    }
}

// ───────────────────────────── publish ─────────────────────────────

pub async fn cmd_publish(args: PublishArgs) -> ExitCode {
    let base_url = resolve_base_url(args.registry.registry.as_deref());
    let creds = match credentials::require(&base_url) {
        Ok(c) => c,
        Err(err) => {
            ui::error(&err.to_string());
            return ExitCode::from(1);
        }
    };

    let source = match std::fs::read(&args.path) {
        Ok(b) => b,
        Err(err) => {
            ui::error(&format!("read {}: {err}", args.path.display()));
            return ExitCode::from(1);
        }
    };
    let source_text = match std::str::from_utf8(&source) {
        Ok(s) => s,
        Err(err) => {
            ui::error(&format!(
                "{} is not valid UTF-8: {err}",
                args.path.display()
            ));
            return ExitCode::from(1);
        }
    };

    let program = match parse(source_text) {
        Ok(p) => p,
        Err(err) => {
            ui::error(&format!("parse {}: {err}", args.path.display()));
            return ExitCode::from(1);
        }
    };
    let name = match script_name(&program) {
        Some(n) => slugify_or_err(&n),
        None => {
            ui::error("script is missing `name \"...\"` in metadata — required to publish");
            return ExitCode::from(1);
        }
    };
    let name = match name {
        Ok(n) => n,
        Err(err) => {
            ui::error(&err);
            return ExitCode::from(1);
        }
    };

    let client = match RegistryClient::new(base_url.clone(), Some(creds.token)) {
        Ok(c) => c,
        Err(err) => {
            ui::error(&err.to_string());
            return ExitCode::from(1);
        }
    };

    let namespace = match args.namespace {
        Some(ns) => ns,
        None => match client.me().await {
            Ok(me) => me.username,
            Err(err) => {
                ui::error(&format!("could not determine namespace from /v1/me: {err}"));
                return ExitCode::from(1);
            }
        },
    };

    let visibility = args.visibility.map(visibility_str);

    match client.publish(&namespace, &name, source, visibility).await {
        Ok(resp) => {
            println!(
                "published {}/{}@{} ({} bytes, {})",
                resp.namespace, resp.name, resp.version, resp.size_bytes, resp.visibility
            );
            if !resp.tags.is_empty() {
                println!("tags:     {}", resp.tags.join(", "));
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            ui::error(&err.to_string());
            ExitCode::from(1)
        }
    }
}

fn script_name(program: &Program) -> Option<String> {
    // First Name metadata wins — matches the compiler's behaviour.
    program.statements.iter().find_map(|s| match s {
        Stmt::Name(n) => Some(n.clone()),
        _ => None,
    })
}

/// Convert a human script name (`"Log4Shell CVE-2021-44228"`) into a
/// registry-safe slug (`log4shell-cve-2021-44228`). The backend re-
/// validates with the same shape so a mismatch here just surfaces a
/// readable client-side error.
fn slugify_or_err(raw: &str) -> Result<String, String> {
    let lowered: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let mut slug = String::with_capacity(lowered.len());
    let mut prev_dash = false;
    for c in lowered.chars() {
        if c == '-' {
            if !prev_dash && !slug.is_empty() {
                slug.push('-');
            }
            prev_dash = true;
        } else {
            slug.push(c);
            prev_dash = false;
        }
    }
    while slug.ends_with('-') {
        slug.pop();
    }
    if slug.is_empty() {
        return Err(format!("cannot derive registry slug from `{raw}`"));
    }
    if slug.len() > 64 {
        slug.truncate(64);
        while slug.ends_with('-') {
            slug.pop();
        }
    }
    Ok(slug)
}

fn visibility_str(v: Visibility) -> &'static str {
    match v {
        Visibility::Public => "public",
        Visibility::Private => "private",
    }
}

// ───────────────────────────── install ─────────────────────────────

pub async fn cmd_install(args: InstallArgs) -> ExitCode {
    let base_url = resolve_base_url(args.registry.registry.as_deref());
    let creds = credentials::load(&base_url).ok().flatten();
    let token = creds.map(|c| c.token);

    let client = match RegistryClient::new(base_url, token) {
        Ok(c) => c,
        Err(err) => {
            ui::error(&err.to_string());
            return ExitCode::from(1);
        }
    };
    let store = match InstallStore::default_for_user() {
        Ok(s) => s,
        Err(err) => {
            ui::error(&err.to_string());
            return ExitCode::from(1);
        }
    };

    let mut had_error = false;
    for raw in &args.refs {
        let r#ref = match parse_ref(raw) {
            Some(r) => r,
            None => {
                ui::error(&format!(
                    "`{raw}` is not a valid registry ref (expected `<ns>/<name>[@<range>]`)"
                ));
                had_error = true;
                continue;
            }
        };
        if args.force {
            // Bust the local cache by removing matching version files; the
            // resolver then falls through to the network. Cheaper than
            // adding a "force=true" knob to the resolver itself.
            if let Err(err) = clear_cached(&store, &r#ref) {
                ui::error(&err.to_string());
                had_error = true;
                continue;
            }
        }
        if args.all_versions {
            match install_all_versions(&store, &client, &r#ref).await {
                Ok(installed) => {
                    if installed.is_empty() {
                        ui::error(&format!(
                            "no non-yanked versions of {} match {}",
                            r#ref.display(),
                            r#ref.range.as_deref().unwrap_or("*"),
                        ));
                        had_error = true;
                    }
                    for (version, path) in installed {
                        println!(
                            "installed {}/{} @ {} -> {}",
                            r#ref.namespace,
                            r#ref.name,
                            version,
                            path.display()
                        );
                    }
                }
                Err(err) => {
                    ui::error(&format!("install {}: {err}", r#ref.display()));
                    had_error = true;
                }
            }
        } else {
            match install_store::install(&store, &client, &r#ref).await {
                Ok((version, path)) => {
                    println!(
                        "installed {}/{} @ {} -> {}",
                        r#ref.namespace,
                        r#ref.name,
                        version,
                        path.display()
                    );
                }
                Err(err) => {
                    ui::error(&format!("install {}: {err}", r#ref.display()));
                    had_error = true;
                }
            }
        }
    }
    if had_error {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// Fetch every non-yanked version of `ref` that matches its range (or all,
/// if the ref has no range) and write them to the cache. Returns the list
/// of `(version, path)` it materialised — already-cached versions count
/// too, since the caller cares about "what's installed now."
async fn install_all_versions(
    store: &InstallStore,
    client: &RegistryClient,
    r#ref: &RegistryRef,
) -> Result<Vec<(semver::Version, std::path::PathBuf)>, String> {
    let script = client
        .show(&r#ref.namespace, &r#ref.name, r#ref.range.as_deref())
        .await
        .map_err(|e| e.to_string())?;
    let req = match r#ref.range.as_deref() {
        None => None,
        Some(r) => Some(
            semver::VersionReq::parse(r).map_err(|e| format!("invalid SemVer range `{r}`: {e}"))?,
        ),
    };
    let mut candidates: Vec<semver::Version> = script
        .versions
        .iter()
        .filter(|v| v.yanked_at.is_none())
        .filter_map(|v| semver::Version::parse(&v.version).ok())
        .filter(|v| req.as_ref().is_none_or(|r| r.matches(v)))
        .collect();
    // Newest first so cancellation mid-stream leaves the most-useful
    // versions behind.
    candidates.sort_by(|a, b| b.cmp(a));

    let mut out = Vec::with_capacity(candidates.len());
    for v in candidates {
        let version_str = v.to_string();
        let cached = store.bytecode_path(&r#ref.namespace, &r#ref.name, &version_str);
        let path = if cached.exists() {
            cached
        } else {
            let bytes = client
                .download_bytecode(&r#ref.namespace, &r#ref.name, &version_str)
                .await
                .map_err(|e| e.to_string())?;
            store
                .write_bytecode(&r#ref.namespace, &r#ref.name, &version_str, &bytes)
                .map_err(|e| e.to_string())?
        };
        out.push((v, path));
    }
    Ok(out)
}

fn clear_cached(store: &InstallStore, r#ref: &RegistryRef) -> Result<(), io::Error> {
    let dir = store.script_dir(&r#ref.namespace, &r#ref.name);
    if !dir.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("bc") {
            std::fs::remove_file(&path)?;
        }
    }
    Ok(())
}

// ───────────────────────────── search ─────────────────────────────

pub async fn cmd_search(args: SearchArgs) -> ExitCode {
    let base_url = resolve_base_url(args.registry.registry.as_deref());
    let token = credentials::load(&base_url).ok().flatten().map(|c| c.token);
    let client = match RegistryClient::new(base_url, token) {
        Ok(c) => c,
        Err(err) => {
            ui::error(&err.to_string());
            return ExitCode::from(1);
        }
    };

    let params = SearchParams {
        q: args.query,
        severity: args.severity,
        cve: args.cve,
        namespace: args.namespace,
        tags: args.tag,
        page: Some(args.page),
        per_page: Some(args.per_page),
    };

    match client.search(&params).await {
        Ok(resp) => {
            if args.json {
                match serde_json::to_string_pretty(&resp.results) {
                    Ok(s) => println!("{s}"),
                    Err(err) => {
                        ui::error(&err.to_string());
                        return ExitCode::from(1);
                    }
                }
            } else {
                print_search_table(&resp);
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            ui::error(&err.to_string());
            ExitCode::from(1)
        }
    }
}

fn print_search_table(resp: &crate::cli::registry::SearchResponse) {
    if resp.results.is_empty() {
        println!("no matches (page {} of total {})", resp.page, resp.total);
        return;
    }
    println!("{:<40} {:<10} {:<10} TAGS", "SCRIPT", "VIS", "SEVERITY");
    for hit in &resp.results {
        let id = format!("{}/{}", hit.namespace, hit.name);
        let sev = hit.severity.clone().unwrap_or_else(|| "-".into());
        let tags = if hit.tags.is_empty() {
            "-".into()
        } else {
            hit.tags.join(",")
        };
        println!("{:<40} {:<10} {:<10} {}", id, hit.visibility, sev, tags);
    }
    let last_page = ((resp.total as u32).max(1)).div_ceil(resp.per_page.max(1));
    println!(
        "\npage {} of {} ({} results)",
        resp.page, last_page, resp.total
    );
}

// ───────────────────────────── shared script resolver ─────────────────────────────

/// Resolved `--script` / `--bytecode` input. The two-variant shape lets the
/// caller pick "compile then run" vs "decode then run" without having to
/// peek at file extensions itself.
pub enum ScriptInput {
    Sources(Vec<PathBuf>),
    Bytecodes(Vec<PathBuf>),
}

/// Resolve a raw `--script` argument to either `.ruso` source files or
/// pre-compiled `.bc` bytecode files. Filesystem paths always win over
/// registry-ref pattern matching, so a local file/dir named like a slug
/// still works.
pub async fn resolve_script_input(
    raw: &str,
    registry: &RegistryArgs,
) -> Result<ScriptInput, String> {
    let path = Path::new(raw);
    if path.exists() {
        // Heuristic: file with `.bc` extension or directory containing
        // `.bc` files → bytecode. Otherwise treat as source. We pick this
        // by extension first; for a directory we just try sources and
        // fall back to bytecodes on EmptyScripts.
        if path.is_file() {
            match path.extension().and_then(|e| e.to_str()) {
                Some("bc") => {
                    return discover_bytecode(path)
                        .map(ScriptInput::Bytecodes)
                        .map_err(|e| e.to_string());
                }
                _ => {
                    return discover_scripts(path)
                        .map(ScriptInput::Sources)
                        .map_err(|e| e.to_string());
                }
            }
        }
        // Directory: prefer .ruso; if none, try .bc.
        match discover_scripts(path) {
            Ok(files) => return Ok(ScriptInput::Sources(files)),
            Err(_) => {
                return discover_bytecode(path)
                    .map(ScriptInput::Bytecodes)
                    .map_err(|e| e.to_string());
            }
        }
    }

    if let Some(r#ref) = parse_ref(raw) {
        let path = resolve_registry_ref(&r#ref, registry).await?;
        return Ok(ScriptInput::Bytecodes(vec![path]));
    }

    Err(format!(
        "`{raw}` is neither an existing path nor a registry ref `<ns>/<name>[@<range>]`"
    ))
}

/// Same for `--bytecode`: paths must already be `.bc`, refs resolve to
/// the cache.
pub async fn resolve_bytecode_input(
    raw: &str,
    registry: &RegistryArgs,
) -> Result<Vec<PathBuf>, String> {
    let path = Path::new(raw);
    if path.exists() {
        return discover_bytecode(path).map_err(|e| e.to_string());
    }
    if let Some(r#ref) = parse_ref(raw) {
        let path = resolve_registry_ref(&r#ref, registry).await?;
        return Ok(vec![path]);
    }
    Err(format!(
        "`{raw}` is neither an existing path nor a registry ref"
    ))
}

async fn resolve_registry_ref(
    r#ref: &RegistryRef,
    registry: &RegistryArgs,
) -> Result<PathBuf, String> {
    let base_url = resolve_base_url(registry.registry.as_deref());
    let token = credentials::load(&base_url).ok().flatten().map(|c| c.token);
    let client = RegistryClient::new(base_url, token).map_err(|e: RegistryError| e.to_string())?;
    let store = InstallStore::default_for_user().map_err(|e| e.to_string())?;
    install_store::resolve_to_path(&store, &client, r#ref)
        .await
        .map_err(|e| e.to_string())
}
