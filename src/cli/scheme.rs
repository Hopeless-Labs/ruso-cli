//! Resolve the URL scheme for bare-host `--target` values.
//!
//! A bare host (`example.com`, `10.0.0.5`) carries no scheme, yet production
//! web is TLS-first. Instead of blindly prepending `http://` (port 80), probe
//! https first and fall back to http **only** when 443 is unreachable at the
//! connection level — never downgrade to cleartext because of a certificate or
//! HTTP-status error (that would be a security regression and, for a host whose
//! only fault is an unverified cert, would wrongly abandon the TLS service).

use std::time::Duration;

use crate::cli::args::DefaultScheme;
use crate::cli::targets;

/// Connect/total budget for a single scheme probe. Kept short so an
/// unreachable port does not stall target resolution.
const PROBE_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const PROBE_TOTAL_TIMEOUT: Duration = Duration::from_secs(8);

/// Resolve each target into a base URL carrying an explicit scheme.
///
/// - A target that already has a scheme is returned unchanged.
/// - A bare host is resolved to `https://` or `http://`:
///   - For a non-HTTP scan (`needs_http == false`) the scheme is irrelevant to
///     socket probes, so the historical `http://` carrier is preserved (this
///     also keeps a socket script's `{{scan_port}}` default at 80).
///   - With `probe == false`, `default_scheme` is applied directly (no network).
///   - Otherwise https is probed first, falling back to http only on a
///     connection-level failure.
pub async fn resolve_targets(
    targets: Vec<String>,
    verify_ssl: bool,
    needs_http: bool,
    default_scheme: DefaultScheme,
    probe: bool,
) -> Vec<String> {
    let mut resolved = Vec::with_capacity(targets.len());
    for target in targets {
        resolved.push(resolve_one(&target, verify_ssl, needs_http, default_scheme, probe).await);
    }
    resolved
}

async fn resolve_one(
    target: &str,
    verify_ssl: bool,
    needs_http: bool,
    default_scheme: DefaultScheme,
    probe: bool,
) -> String {
    // Already a URL: honor the user's explicit scheme/port untouched.
    if targets::is_url(target) {
        return target.to_string();
    }
    // Pure socket scan: the carrier scheme never reaches the wire, so keep the
    // legacy http:// form (and the implied port-80 `{{scan_port}}` default).
    if !needs_http {
        return format!("http://{target}");
    }
    if !probe {
        return format!("{}://{target}", default_scheme.as_str());
    }

    let https = format!("https://{target}");
    // Happy path: one probe, honoring the user's TLS-verify setting.
    if probe_responds(&https, verify_ssl).await {
        return https;
    }
    // The verify-honoring probe failed. Re-probe ignoring the certificate to
    // tell a cert problem (443 is up) apart from a dead port.
    if probe_responds(&https, false).await {
        if verify_ssl {
            tracing::warn!(
                "{target}: 443 is reachable but its TLS certificate did not verify; \
                 scanning over https — pass --insecure to complete the scan"
            );
        }
        // 443 speaks TLS+HTTP; stay on https rather than downgrade to cleartext.
        return https;
    }
    // 443 is genuinely unreachable; try cleartext http.
    let http = format!("http://{target}");
    if probe_responds(&http, true).await {
        return http;
    }
    // Neither port answered (host down/filtered): fall back to the default.
    format!("{}://{target}", default_scheme.as_str())
}

/// True if a GET to `url` elicits any HTTP response. Any status counts — we are
/// probing reachability of the scheme/port, not the result. Redirects are not
/// followed (a 3xx still proves the port answers).
async fn probe_responds(url: &str, verify_ssl: bool) -> bool {
    let client = match reqwest::Client::builder()
        .connect_timeout(PROBE_CONNECT_TIMEOUT)
        .timeout(PROBE_TOTAL_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(!verify_ssl)
        .build()
    {
        Ok(client) => client,
        Err(_) => return false,
    };
    client.get(url).send().await.is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn url_targets_pass_through_unchanged() {
        let out = resolve_targets(
            vec!["https://a.example".into(), "http://b.example:8080".into()],
            true,
            true,
            DefaultScheme::Https,
            true,
        )
        .await;
        assert_eq!(out, vec!["https://a.example", "http://b.example:8080"]);
    }

    #[tokio::test]
    async fn socket_scan_keeps_http_carrier() {
        // needs_http == false -> bare host keeps the http:// carrier verbatim.
        let out = resolve_targets(
            vec!["db.internal:6379".into()],
            true,
            false,
            DefaultScheme::Https,
            true,
        )
        .await;
        assert_eq!(out, vec!["http://db.internal:6379"]);
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
        let out =
            resolve_targets(vec![target.clone()], true, true, DefaultScheme::Https, true).await;
        assert_eq!(out, vec![format!("http://{target}")]);
    }

    #[tokio::test]
    async fn probe_disabled_applies_default_scheme() {
        let https = resolve_targets(
            vec!["x.example".into()],
            true,
            true,
            DefaultScheme::Https,
            false,
        )
        .await;
        assert_eq!(https, vec!["https://x.example"]);
        let http = resolve_targets(
            vec!["x.example".into()],
            true,
            true,
            DefaultScheme::Http,
            false,
        )
        .await;
        assert_eq!(http, vec!["http://x.example"]);
    }
}
