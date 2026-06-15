//! Handlers for `ruso login/logout/whoami/publish/install/search` and the
//! shared helpers that wire registry references (`<ns>/<name>[@<range>]`)
//! into `scan` and `exec`.

use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ruso_script::{Program, Stmt, parse};

use crate::cli::args::{
    AdminDeleteArgs, EditArgs, InfoArgs, InstallArgs, LoginArgs, PatCreateArgs, PatListArgs,
    PatRevokeArgs, PublishArgs, RegistryArgs, RegistryOnlyArgs, SearchArgs, UnyankArgs, Visibility,
    YankArgs,
};
use crate::cli::credentials::{self, Credentials};
use crate::cli::discover::{discover_bytecode, discover_scripts};
use crate::cli::install_store::{self, CacheMode, InstallStore, RegistryRef, parse_ref};
use crate::cli::registry::{
    CreateTokenRequest, PatchScriptRequest, RegistryClient, RegistryError, ScriptResponse,
    SearchParams, TokenSummary, resolve_base_url,
};
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
    let me = match ui::with_spinner("verifying token", client.me()).await {
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
    match ui::with_spinner("loading account", client.me()).await {
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

    // Namespace is always the caller's own username — the registry has
    // no organizations, so a script can only be published under you.
    let namespace = match client.me().await {
        Ok(me) => me.username,
        Err(err) => {
            ui::error(&format!("could not determine namespace from /v1/me: {err}"));
            return ExitCode::from(1);
        }
    };

    let visibility = args.visibility.map(visibility_str);

    match ui::with_spinner(
        "publishing",
        client.publish(&namespace, &name, source, visibility),
    )
    .await
    {
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
    // Cap at the registry's slug limit (backend `SCRIPT_NAME` is
    // `^[a-z0-9][a-z0-9-]{0,38}$`, i.e. max 39 chars). Truncating to a
    // larger value here would only push the rejection to the server as a
    // 400; trim client-side so the derived slug is always publishable.
    if slug.len() > 39 {
        slug.truncate(39);
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
        let cache = if args.force {
            CacheMode::Force
        } else {
            CacheMode::UseCache
        };
        if args.all_versions {
            match ui::with_spinner(
                "installing",
                install_all_versions(&store, &client, &r#ref, cache),
            )
            .await
            {
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
            match ui::with_spinner(
                "installing",
                install_store::install_with(&store, &client, &r#ref, cache),
            )
            .await
            {
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
    cache: CacheMode,
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
        let path = if cache == CacheMode::UseCache && cached.exists() {
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
        family: args.family,
        tags: args.tag,
        page: Some(args.page),
        per_page: Some(args.per_page),
    };

    match ui::with_spinner("searching", client.search(&params)).await {
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
    println!(
        "{:<40} {:<10} {:<10} {:<10} TAGS",
        "SCRIPT", "VIS", "SEVERITY", "FAMILY"
    );
    for hit in &resp.results {
        let id = format!("{}/{}", hit.namespace, hit.name);
        let sev = hit.severity.clone().unwrap_or_else(|| "-".into());
        let fam = hit.family.clone().unwrap_or_else(|| "-".into());
        let tags = if hit.tags.is_empty() {
            "-".into()
        } else {
            hit.tags.join(",")
        };
        println!(
            "{:<40} {:<10} {:<10} {:<10} {}",
            id, hit.visibility, sev, fam, tags
        );
    }
    let last_page = ((resp.total as u32).max(1)).div_ceil(resp.per_page.max(1));
    println!(
        "\npage {} of {} ({} results)",
        resp.page, last_page, resp.total
    );
}

// ───────────────────────────── info / yank / unyank / edit ─────────────────────────────

pub async fn cmd_info(args: InfoArgs) -> ExitCode {
    let (ns, name, range) = match parse_ns_name_optional_range(&args.r#ref) {
        Ok(parts) => parts,
        Err(msg) => {
            ui::error(&msg);
            return ExitCode::from(1);
        }
    };
    let base_url = resolve_base_url(args.registry.registry.as_deref());
    let token = credentials::load(&base_url).ok().flatten().map(|c| c.token);
    let client = match RegistryClient::new(base_url, token) {
        Ok(c) => c,
        Err(err) => {
            ui::error(&err.to_string());
            return ExitCode::from(1);
        }
    };

    match ui::with_spinner("loading", client.show(&ns, &name, range.as_deref())).await {
        Ok(script) => {
            if args.json {
                match serde_json::to_string_pretty(&script) {
                    Ok(s) => println!("{s}"),
                    Err(err) => {
                        ui::error(&err.to_string());
                        return ExitCode::from(1);
                    }
                }
            } else {
                print_info_human(&script);
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            ui::error(&err.to_string());
            ExitCode::from(1)
        }
    }
}

fn print_info_human(s: &ScriptResponse) {
    println!("{}/{}", s.namespace, s.name);
    println!("  visibility: {}", s.visibility);
    if let Some(fam) = &s.family
        && !fam.is_empty()
    {
        println!("  family: {fam}");
    }
    if let Some(d) = &s.description
        && !d.is_empty()
    {
        println!("  description: {d}");
    }
    if !s.tags.is_empty() {
        println!("  tags: {}", s.tags.join(", "));
    }
    let latest = s.versions.iter().find(|v| v.yanked_at.is_none());
    if let Some(v) = latest {
        println!("  latest: {} ({} downloads)", v.version, v.download_count);
        println!();
        println!("  install:");
        println!("    ruso install {}/{}", s.namespace, s.name);
        println!(
            "    ruso scan --script {}/{} --target https://example.com",
            s.namespace, s.name
        );
    }
    println!();
    println!("  versions ({}):", s.versions.len());
    for v in &s.versions {
        let yank = if v.yanked_at.is_some() { " yanked" } else { "" };
        println!(
            "    {:<14} {:>10} downloads  {} bytes{}",
            v.version, v.download_count, v.size_bytes, yank
        );
    }
}

pub async fn cmd_yank(args: YankArgs) -> ExitCode {
    let (ns, name, version) = match parse_ns_name_version(&args.r#ref) {
        Ok(parts) => parts,
        Err(msg) => {
            ui::error(&msg);
            return ExitCode::from(1);
        }
    };
    let Some(client) = require_authed_client(&args.registry).await else {
        return ExitCode::from(1);
    };
    match ui::with_spinner(
        "yanking",
        client.yank_version(&ns, &name, &version, args.reason.as_deref()),
    )
    .await
    {
        Ok(()) => {
            println!("yanked {}/{}@{}", ns, name, version);
            ExitCode::SUCCESS
        }
        Err(err) => {
            ui::error(&err.to_string());
            ExitCode::from(1)
        }
    }
}

pub async fn cmd_unyank(args: UnyankArgs) -> ExitCode {
    let (ns, name, version) = match parse_ns_name_version(&args.r#ref) {
        Ok(parts) => parts,
        Err(msg) => {
            ui::error(&msg);
            return ExitCode::from(1);
        }
    };
    let Some(client) = require_authed_client(&args.registry).await else {
        return ExitCode::from(1);
    };
    match ui::with_spinner("unyanking", client.unyank_version(&ns, &name, &version)).await {
        Ok(()) => {
            println!("unyanked {}/{}@{}", ns, name, version);
            ExitCode::SUCCESS
        }
        Err(err) => {
            ui::error(&err.to_string());
            ExitCode::from(1)
        }
    }
}

pub async fn cmd_admin_delete(args: AdminDeleteArgs) -> ExitCode {
    // `<ns>/<name>` → delete the whole script; `<ns>/<name>@<version>` →
    // delete that one version.
    let (ns, name, version) = match parse_ns_name_optional_range(&args.r#ref) {
        Ok(parts) => parts,
        Err(msg) => {
            ui::error(&msg);
            return ExitCode::from(1);
        }
    };
    let target = match &version {
        Some(v) => format!("{ns}/{name}@{v}"),
        None => format!("{ns}/{name} (and ALL its versions)"),
    };
    if !args.yes {
        ui::error(&format!(
            "refusing to hard-delete {target} without --yes (this is irreversible)"
        ));
        return ExitCode::from(1);
    }
    let Some(client) = require_authed_client(&args.registry).await else {
        return ExitCode::from(1);
    };
    let result = match &version {
        Some(v) => {
            ui::with_spinner("deleting", client.admin_delete_version(&ns, &name, v)).await
        }
        None => ui::with_spinner("deleting", client.admin_delete_script(&ns, &name)).await,
    };
    match result {
        Ok(()) => {
            println!("deleted {target}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            ui::error(&err.to_string());
            ExitCode::from(1)
        }
    }
}

pub async fn cmd_edit(args: EditArgs) -> ExitCode {
    if args.description.is_none() && args.visibility.is_none() {
        ui::error("nothing to change — pass --description and/or --visibility");
        return ExitCode::from(1);
    }
    let (ns, name, _range) = match parse_ns_name_optional_range(&args.r#ref) {
        Ok(parts) => parts,
        Err(msg) => {
            ui::error(&msg);
            return ExitCode::from(1);
        }
    };
    let Some(client) = require_authed_client(&args.registry).await else {
        return ExitCode::from(1);
    };

    let body = PatchScriptRequest {
        description: args.description.map(|s| s.trim().to_string()),
        visibility: args.visibility.map(|v| visibility_str(v).to_string()),
    };
    match ui::with_spinner("updating", client.patch_script(&ns, &name, &body)).await {
        Ok(s) => {
            println!("updated {}/{}", s.namespace, s.name);
            if let Some(d) = &body.description {
                if d.is_empty() {
                    println!("  description: (cleared)");
                } else {
                    println!("  description: {d}");
                }
            }
            if let Some(v) = &body.visibility {
                println!("  visibility:  {v}");
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            ui::error(&err.to_string());
            ExitCode::from(1)
        }
    }
}

/// `<ns>/<name>[@<range>]` for read-side ops where a range filter is
/// optional. Returns `(ns, name, range)`.
fn parse_ns_name_optional_range(s: &str) -> Result<(String, String, Option<String>), String> {
    let r = parse_ref(s)
        .ok_or_else(|| format!("`{s}` is not a registry ref (expected `<ns>/<name>[@<range>]`)"))?;
    Ok((r.namespace, r.name, r.range))
}

/// `<ns>/<name>@<version>` for yank-family ops where an exact version
/// is required (not a range). The backend will validate SemVer.
fn parse_ns_name_version(s: &str) -> Result<(String, String, String), String> {
    let r = parse_ref(s)
        .ok_or_else(|| format!("`{s}` is not a registry ref (expected `<ns>/<name>@<version>`)"))?;
    let version = r.range.ok_or_else(|| {
        format!("`{s}` is missing `@<version>` — yank/unyank operate on a single version")
    })?;
    Ok((r.namespace, r.name, version))
}

// ───────────────────────────── pat (list / create / revoke) ─────────────────────────────

const ALLOWED_SCOPES: &[&str] = &["read", "publish", "yank"];

pub async fn cmd_pat_list(args: PatListArgs) -> ExitCode {
    let Some(client) = require_authed_client(&args.registry).await else {
        return ExitCode::from(1);
    };
    match ui::with_spinner("loading tokens", client.list_tokens()).await {
        Ok(mut tokens) => {
            if args.active_only {
                tokens.retain(|t| t.revoked_at.is_none());
            }
            // Newest-first so the latest mint is at the top — that's
            // typically what you just created and want to copy the id of.
            tokens.sort_by(|a, b| b.created_at.cmp(&a.created_at));
            if args.json {
                #[derive(serde::Serialize)]
                struct WireToken<'a> {
                    id: &'a str,
                    name: &'a str,
                    scopes: &'a [String],
                    expires_at: Option<&'a str>,
                    created_at: &'a str,
                    last_used_at: Option<&'a str>,
                    revoked_at: Option<&'a str>,
                }
                let wire: Vec<_> = tokens
                    .iter()
                    .map(|t| WireToken {
                        id: &t.id,
                        name: &t.name,
                        scopes: &t.scopes,
                        expires_at: t.expires_at.as_deref(),
                        created_at: &t.created_at,
                        last_used_at: t.last_used_at.as_deref(),
                        revoked_at: t.revoked_at.as_deref(),
                    })
                    .collect();
                match serde_json::to_string_pretty(&wire) {
                    Ok(s) => println!("{s}"),
                    Err(err) => {
                        ui::error(&err.to_string());
                        return ExitCode::from(1);
                    }
                }
            } else {
                print_pat_table(&tokens);
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            ui::error(&err.to_string());
            ExitCode::from(1)
        }
    }
}

pub async fn cmd_pat_create(args: PatCreateArgs) -> ExitCode {
    let Some(client) = require_authed_client(&args.registry).await else {
        return ExitCode::from(1);
    };
    let name = args.name.trim().to_string();
    if name.is_empty() {
        ui::error("token name must not be empty");
        return ExitCode::from(1);
    }
    // Empty `--scope` defaults to `read` — most CLI users only want to
    // install, not publish/yank.
    let scopes: Vec<String> = if args.scope.is_empty() {
        vec!["read".to_string()]
    } else {
        let mut out = Vec::with_capacity(args.scope.len());
        for s in args.scope {
            let s = s.trim().to_lowercase();
            if !ALLOWED_SCOPES.contains(&s.as_str()) {
                ui::error(&format!(
                    "unknown scope `{s}` (allowed: {})",
                    ALLOWED_SCOPES.join(", ")
                ));
                return ExitCode::from(1);
            }
            if !out.contains(&s) {
                out.push(s);
            }
        }
        out
    };

    let req = CreateTokenRequest {
        name: name.clone(),
        scopes: scopes.clone(),
        expires_at: args.expires_at,
    };
    match ui::with_spinner("creating token", client.create_token(&req)).await {
        Ok(resp) => {
            println!(
                "created PAT `{}` (id {}, scopes: {})",
                resp.name,
                resp.id,
                resp.scopes.join(", ")
            );
            println!();
            println!("Store this token now — it won't be shown again:");
            println!("  {}", resp.token);
            ExitCode::SUCCESS
        }
        Err(RegistryError::Http { status: 403, .. }) => {
            // Backend reserves `create` to session-auth only — a PAT
            // can't mint another PAT (would let a leaked token spawn
            // siblings). The active stored credential is presumably
            // a PAT; tell the user how to recover.
            ui::error(
                "minting a new PAT requires a session token (ruso_sess_…) — the \
                 stored credential looks like a PAT. Sign in via the web UI \
                 (Tokens page), or run `ruso login` with a session token.",
            );
            ExitCode::from(1)
        }
        Err(err) => {
            ui::error(&err.to_string());
            ExitCode::from(1)
        }
    }
}

pub async fn cmd_pat_revoke(args: PatRevokeArgs) -> ExitCode {
    let Some(client) = require_authed_client(&args.registry).await else {
        return ExitCode::from(1);
    };
    match ui::with_spinner("revoking token", client.revoke_token(&args.id)).await {
        Ok(()) => {
            println!("revoked {}", args.id);
            ExitCode::SUCCESS
        }
        Err(err) => {
            ui::error(&err.to_string());
            ExitCode::from(1)
        }
    }
}

/// Common preamble for the three pat handlers: resolve registry,
/// require a stored credential, build a client. Returns `None` on any
/// failure (after printing the error) so the caller can short-circuit.
async fn require_authed_client(registry: &RegistryArgs) -> Option<RegistryClient> {
    let base_url = resolve_base_url(registry.registry.as_deref());
    let creds = match credentials::require(&base_url) {
        Ok(c) => c,
        Err(err) => {
            ui::error(&err.to_string());
            return None;
        }
    };
    match RegistryClient::new(base_url, Some(creds.token)) {
        Ok(c) => Some(c),
        Err(err) => {
            ui::error(&err.to_string());
            None
        }
    }
}

fn print_pat_table(tokens: &[TokenSummary]) {
    if tokens.is_empty() {
        println!("no tokens");
        return;
    }
    println!("{:<38} {:<20} {:<22} STATUS", "ID", "NAME", "SCOPES");
    for t in tokens {
        let status = match (&t.revoked_at, &t.expires_at) {
            (Some(_), _) => "revoked".to_string(),
            (None, Some(exp)) => format!("expires {}", exp.split('T').next().unwrap_or(exp)),
            (None, None) => "active".to_string(),
        };
        println!(
            "{:<38} {:<20} {:<22} {}",
            t.id,
            truncate(&t.name, 20),
            truncate(&t.scopes.join(","), 22),
            status,
        );
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(n.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

// ───────────────────────────── shared script resolver ─────────────────────────────

/// Resolved `--script` / `--bytecode` input. The two-variant shape lets the
/// caller pick "compile then run" vs "decode then run" without having to
/// peek at file extensions itself.
pub enum ScriptInput {
    Sources(Vec<PathBuf>),
    Bytecodes(Vec<PathBuf>),
}

/// Resolve a raw `--script` argument to either `.rsl` source files or
/// pre-compiled `.rbc` bytecode files. Filesystem paths always win over
/// registry-ref pattern matching, so a local file/dir named like a slug
/// still works.
pub async fn resolve_script_input(
    raw: &str,
    registry: &RegistryArgs,
) -> Result<ScriptInput, String> {
    let path = Path::new(raw);
    if path.exists() {
        // Heuristic: file with `.rbc` extension or directory containing
        // `.rbc` files → bytecode. Otherwise treat as source. We pick this
        // by extension first; for a directory we just try sources and
        // fall back to bytecodes on EmptyScripts.
        if path.is_file() {
            match path.extension().and_then(|e| e.to_str()) {
                Some("rbc") => {
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
        // Directory: prefer .rsl; if none, try .rbc.
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

/// Same for `--bytecode`: paths must already be `.rbc`, refs resolve to
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

/// Resolve every published script in `family` to a local `.rbc` path,
/// installing each into the cache on the way. Used by `scan --family`.
/// Returns an error if the family has no scripts (so the scan doesn't
/// silently no-op).
pub async fn resolve_family_to_bytecodes(
    family: &str,
    registry: &RegistryArgs,
) -> Result<Vec<PathBuf>, String> {
    let base_url = resolve_base_url(registry.registry.as_deref());
    let token = credentials::load(&base_url).ok().flatten().map(|c| c.token);
    let client = RegistryClient::new(base_url, token).map_err(|e: RegistryError| e.to_string())?;
    let store = InstallStore::default_for_user().map_err(|e| e.to_string())?;

    // Page through the whole family (the registry caps a page at 100), so a
    // family larger than one page isn't silently truncated. Stop on an empty
    // or short page, or once every result the registry reported is collected.
    let results = ui::with_spinner("fetching family", async {
        let mut all = Vec::new();
        let mut page = 1u32;
        loop {
            let params = SearchParams {
                family: Some(family.to_string()),
                per_page: Some(100),
                page: Some(page),
                ..Default::default()
            };
            let resp = client
                .search(&params)
                .await
                .map_err(|e: RegistryError| e.to_string())?;
            let got = resp.results.len();
            let per_page = resp.per_page.max(1) as usize;
            let total = resp.total;
            all.extend(resp.results);
            if got == 0 || got < per_page || (total >= 0 && all.len() as i64 >= total) {
                break;
            }
            page += 1;
        }
        Ok::<_, String>(all)
    })
    .await?;
    if results.is_empty() {
        return Err(format!("no scripts found in family `{family}`"));
    }

    // Download each family member, with a progress spinner over the set. Skip
    // messages are deferred and printed after the spinner stops so a live
    // spinner line never garbles them.
    let (spinner, counter) = ui::Spinner::with_progress("fetching family scripts", results.len());
    let mut paths = Vec::with_capacity(results.len());
    let mut skipped = Vec::new();
    for hit in &results {
        let r#ref = RegistryRef {
            namespace: hit.namespace.clone(),
            name: hit.name.clone(),
            range: None,
        };
        match install_store::resolve_to_path(&store, &client, &r#ref).await {
            Ok(p) => paths.push(p),
            // One bad script shouldn't sink the whole family scan — note it and
            // carry on with the rest.
            Err(e) => skipped.push(format!("skip {}/{}: {e}", hit.namespace, hit.name)),
        }
        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    drop(spinner);
    for message in skipped {
        ui::error(&message);
    }
    if paths.is_empty() {
        return Err(format!(
            "every script in family `{family}` failed to install"
        ));
    }
    Ok(paths)
}
