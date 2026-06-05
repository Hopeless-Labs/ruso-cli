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

use std::time::Duration;

use crate::cli::args::DefaultScheme;
use crate::cli::targets;

/// Total budget for one scheme probe. Short so an unreachable port does not
/// stall target resolution.
const PROBE_TIMEOUT: Duration = Duration::from_secs(8);

/// Inputs controlling bare-host scheme resolution, bundled so the per-target
/// resolver is not a wall of positional booleans.
#[derive(Clone, Copy)]
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

/// Resolve one target into a base URL carrying an explicit scheme, plus — if
/// 443 answered but its cert did not verify — the warning message the caller
/// should print.
///
/// Targets that already have a scheme are returned unchanged. The scan pipeline
/// calls this lazily (once per target, memoised) so resolution overlaps with
/// scanning instead of running as a separate up-front phase.
pub async fn resolve_one(target: &str, opts: &ResolveOptions<'_>) -> (String, Option<String>) {
    // Already a URL: honor the user's explicit scheme/port untouched.
    if targets::is_url(target) {
        return (target.to_string(), None);
    }
    // Pure socket scan: the carrier scheme never reaches the wire, so keep the
    // legacy http:// form (and the implied port-80 `{{scan_port}}` default).
    if !opts.needs_http {
        return (format!("http://{target}"), None);
    }
    if !opts.probe {
        return (format!("{}://{target}", opts.default_scheme.as_str()), None);
    }

    let https = format!("https://{target}");
    // Happy path: one probe, honoring the user's TLS-verify setting.
    if probe_responds(&https, opts.verify_ssl, opts.proxy).await {
        return (https, None);
    }
    // The verify-honoring probe failed. Re-probe ignoring the certificate to
    // tell a cert problem (443 is up) apart from a dead port.
    if probe_responds(&https, false, opts.proxy).await {
        let warning = opts.verify_ssl.then(|| {
            format!(
                "{target}: 443 is reachable but its TLS certificate did not verify; \
                 scanning over https — pass --insecure to complete the scan"
            )
        });
        // 443 speaks TLS+HTTP; stay on https rather than downgrade to cleartext.
        return (https, warning);
    }
    // 443 is genuinely unreachable; try cleartext http.
    let http = format!("http://{target}");
    if probe_responds(&http, true, opts.proxy).await {
        return (http, None);
    }
    // Neither port answered (host down/filtered): fall back to the default.
    (format!("{}://{target}", opts.default_scheme.as_str()), None)
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
        let (url, warning) = resolve_one("https://a.example", &http_scan_opts()).await;
        assert_eq!(url, "https://a.example");
        assert!(warning.is_none());

        let (url, _) = resolve_one("http://b.example:8080", &http_scan_opts()).await;
        assert_eq!(url, "http://b.example:8080");
    }

    #[tokio::test]
    async fn socket_scan_keeps_http_carrier() {
        // needs_http == false -> bare host keeps the http:// carrier verbatim.
        let opts = ResolveOptions {
            needs_http: false,
            ..http_scan_opts()
        };
        let (url, _) = resolve_one("db.internal:6379", &opts).await;
        assert_eq!(url, "http://db.internal:6379");
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
        let (url, _) = resolve_one(&target, &http_scan_opts()).await;
        assert_eq!(url, format!("http://{target}"));
    }

    #[tokio::test]
    async fn probe_disabled_applies_default_scheme() {
        let (https, _) = resolve_one(
            "x.example",
            &ResolveOptions {
                probe: false,
                ..http_scan_opts()
            },
        )
        .await;
        assert_eq!(https, "https://x.example");

        let (http, _) = resolve_one(
            "x.example",
            &ResolveOptions {
                probe: false,
                default_scheme: DefaultScheme::Http,
                ..http_scan_opts()
            },
        )
        .await;
        assert_eq!(http, "http://x.example");
    }
}
