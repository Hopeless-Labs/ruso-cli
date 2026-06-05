//! Resolve the URL scheme for bare-host `--target` values.
//!
//! A bare host (`example.com`, `10.0.0.5`) carries no scheme, yet production
//! web is TLS-first. Instead of blindly prepending `http://` (port 80), probe
//! https first and fall back to http **only** when 443 is unreachable at the
//! connection level — never downgrade to cleartext because of a certificate or
//! HTTP-status error (that would be a security regression and, for a host whose
//! only fault is an unverified cert, would wrongly abandon the TLS service).
//!
//! This module owns the resolution *policy*; the actual client (TLS, proxy,
//! redirects) comes from [`ruso_runtime::build_client`] so probes behave
//! exactly like the executor's real requests.

use std::collections::HashSet;
use std::time::Duration;

use crate::cli::args::DefaultScheme;
use crate::cli::{targets, ui};

/// Total budget for one scheme probe. Short so an unreachable port does not
/// stall target resolution.
const PROBE_TIMEOUT: Duration = Duration::from_secs(8);

/// Inputs controlling bare-host scheme resolution, bundled so the per-target
/// resolver is not a wall of positional booleans.
pub struct ResolveOptions<'a> {
    /// Verify TLS certificates while probing (mirrors the scan's `--insecure`).
    pub verify_ssl: bool,
    /// Whether any script in the run makes HTTP requests. When false the scheme
    /// never reaches the wire (socket-only scan) and the legacy `http://`
    /// carrier is kept.
    pub needs_http: bool,
    /// Scheme applied when probing is disabled or no port answers.
    pub default_scheme: DefaultScheme,
    /// Run the https-first connectivity probe. When false, apply `default_scheme`.
    pub probe: bool,
    /// HTTP proxy to route probes through (mirrors the scan's `--proxy`).
    pub proxy: Option<&'a str>,
}

/// Outcome of resolving a batch of targets.
pub struct Resolved {
    /// Each target rewritten into a base URL carrying an explicit scheme.
    pub urls: Vec<String>,
    /// Resolved URLs the probe already warned about because 443 answered but
    /// its TLS certificate did not verify. The scan pipeline uses this to
    /// suppress a second, redundant `--insecure` hint for the same target.
    pub cert_warned: HashSet<String>,
}

/// Resolve each target into a base URL carrying an explicit scheme.
///
/// Targets that already have a scheme are returned unchanged; bare hosts are
/// resolved per [`ResolveOptions`].
pub async fn resolve_targets(targets: Vec<String>, opts: &ResolveOptions<'_>) -> Resolved {
    let mut urls = Vec::with_capacity(targets.len());
    let mut cert_warned = HashSet::new();
    for target in targets {
        let (url, warned) = resolve_one(&target, opts).await;
        if warned {
            cert_warned.insert(url.clone());
        }
        urls.push(url);
    }
    Resolved { urls, cert_warned }
}

/// Returns the resolved URL and whether a TLS-certificate warning was emitted
/// for it (443 reachable but cert unverified).
async fn resolve_one(target: &str, opts: &ResolveOptions<'_>) -> (String, bool) {
    // Already a URL: honor the user's explicit scheme/port untouched.
    if targets::is_url(target) {
        return (target.to_string(), false);
    }
    // Pure socket scan: the carrier scheme never reaches the wire, so keep the
    // legacy http:// form (and the implied port-80 `{{scan_port}}` default).
    if !opts.needs_http {
        return (format!("http://{target}"), false);
    }
    if !opts.probe {
        return (
            format!("{}://{target}", opts.default_scheme.as_str()),
            false,
        );
    }

    let https = format!("https://{target}");
    // Happy path: one probe, honoring the user's TLS-verify setting.
    if probe_responds(&https, opts.verify_ssl, opts.proxy).await {
        return (https, false);
    }
    // The verify-honoring probe failed. Re-probe ignoring the certificate to
    // tell a cert problem (443 is up) apart from a dead port.
    if probe_responds(&https, false, opts.proxy).await {
        let warned = opts.verify_ssl;
        if warned {
            ui::warn(&format!(
                "{target}: 443 is reachable but its TLS certificate did not verify; \
                 scanning over https — pass --insecure to complete the scan"
            ));
        }
        // 443 speaks TLS+HTTP; stay on https rather than downgrade to cleartext.
        return (https, warned);
    }
    // 443 is genuinely unreachable; try cleartext http.
    let http = format!("http://{target}");
    if probe_responds(&http, true, opts.proxy).await {
        return (http, false);
    }
    // Neither port answered (host down/filtered): fall back to the default.
    (
        format!("{}://{target}", opts.default_scheme.as_str()),
        false,
    )
}

/// True if a GET to `url` elicits any HTTP response. Any status counts — we are
/// probing reachability of the scheme/port, not the result. The client mirrors
/// the executor (proxy, TLS) but never follows redirects (a 3xx still proves
/// the port answers).
async fn probe_responds(url: &str, verify_ssl: bool, proxy: Option<&str>) -> bool {
    let Ok(client) = ruso_runtime::build_client(Some(PROBE_TIMEOUT), false, verify_ssl, proxy)
    else {
        return false;
    };
    client.get(url).send().await.is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ResolveOptions` for an HTTP scan with probing on, verifying TLS, no proxy.
    fn http_scan_opts() -> ResolveOptions<'static> {
        ResolveOptions {
            verify_ssl: true,
            needs_http: true,
            default_scheme: DefaultScheme::Https,
            probe: true,
            proxy: None,
        }
    }

    #[tokio::test]
    async fn url_targets_pass_through_unchanged() {
        let out = resolve_targets(
            vec!["https://a.example".into(), "http://b.example:8080".into()],
            &http_scan_opts(),
        )
        .await;
        assert_eq!(out.urls, vec!["https://a.example", "http://b.example:8080"]);
        assert!(out.cert_warned.is_empty());
    }

    #[tokio::test]
    async fn socket_scan_keeps_http_carrier() {
        // needs_http == false -> bare host keeps the http:// carrier verbatim.
        let opts = ResolveOptions {
            needs_http: false,
            ..http_scan_opts()
        };
        let out = resolve_targets(vec!["db.internal:6379".into()], &opts).await;
        assert_eq!(out.urls, vec!["http://db.internal:6379"]);
    }

    #[tokio::test]
    async fn bare_host_falls_back_to_http_when_443_dead() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        // A plaintext-HTTP responder on an ephemeral port. The two https probes
        // open a TCP connection but fail the TLS handshake (no TLS here) and are
        // dropped; the cleartext http probe gets a real 200, so resolution must
        // pick http. The responder runs on a detached thread that the test
        // process reaps on exit.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for mut sock in listener.incoming().flatten() {
                let _ = sock.set_read_timeout(Some(Duration::from_millis(300)));
                let mut buf = [0u8; 256];
                let _ = sock.read(&mut buf);
                let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            }
        });

        let target = format!("127.0.0.1:{port}");
        let out = resolve_targets(vec![target.clone()], &http_scan_opts()).await;
        assert_eq!(out.urls, vec![format!("http://{target}")]);
    }

    #[tokio::test]
    async fn probe_disabled_applies_default_scheme() {
        let https = resolve_targets(
            vec!["x.example".into()],
            &ResolveOptions {
                probe: false,
                ..http_scan_opts()
            },
        )
        .await;
        assert_eq!(https.urls, vec!["https://x.example"]);

        let http = resolve_targets(
            vec!["x.example".into()],
            &ResolveOptions {
                probe: false,
                default_scheme: DefaultScheme::Http,
                ..http_scan_opts()
            },
        )
        .await;
        assert_eq!(http.urls, vec!["http://x.example"]);
    }
}
