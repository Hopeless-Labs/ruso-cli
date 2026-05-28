//! HTTP client for the Ruso registry backend.
//!
//! Thin wrapper over reqwest: every method that hits the wire returns
//! a typed response struct or a `RegistryError`. Authentication is
//! header-only — `Authorization: Bearer <token>` — sessions and PATs
//! share the same shape on the wire (the backend dispatches based on
//! the prefix).

use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Hardcoded default for MVP. Override with `--registry` or
/// `RUSO_REGISTRY_URL`. Once we have a hosted instance, change this.
pub const DEFAULT_REGISTRY: &str = "http://127.0.0.1:8080";

const USER_AGENT: &str = concat!("ruso-cli/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("invalid registry URL `{url}`: {reason}")]
    BadUrl { url: String, reason: String },
    #[error("registry returned {status} at {path}: {body}")]
    Http {
        status: u16,
        path: String,
        body: String,
    },
    #[error("authentication required (run `ruso login --token …`)")]
    Unauthorized,
    #[error("decode error: {0}")]
    Decode(String),
}

/// Resolve which registry to talk to. Priority: explicit flag, env, default.
pub fn resolve_base_url(flag: Option<&str>) -> String {
    if let Some(v) = flag {
        return strip_trailing_slash(v);
    }
    if let Ok(v) = std::env::var("RUSO_REGISTRY_URL")
        && !v.is_empty()
    {
        return strip_trailing_slash(&v);
    }
    DEFAULT_REGISTRY.to_string()
}

fn strip_trailing_slash(s: &str) -> String {
    s.trim_end_matches('/').to_string()
}

pub struct RegistryClient {
    base_url: String,
    http: reqwest::Client,
    token: Option<String>,
}

impl RegistryClient {
    /// Build a client for `base_url`. If `token` is Some, all requests will
    /// carry an `Authorization: Bearer` header.
    pub fn new(base_url: String, token: Option<String>) -> Result<Self, RegistryError> {
        // Validate the base URL up-front so the first error a user sees
        // is "your URL is bad" rather than a deep DNS failure later.
        reqwest::Url::parse(&base_url).map_err(|err| RegistryError::BadUrl {
            url: base_url.clone(),
            reason: err.to_string(),
        })?;

        let http = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(Duration::from_secs(60))
            .build()?;
        Ok(Self {
            base_url,
            http,
            token,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let mut req = self.http.request(method, self.url(path));
        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }
        req
    }

    async fn json_response<T: for<'de> Deserialize<'de>>(
        resp: reqwest::Response,
        path: &str,
    ) -> Result<T, RegistryError> {
        let status = resp.status();
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(RegistryError::Unauthorized);
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(RegistryError::Http {
                status: status.as_u16(),
                path: path.to_string(),
                body,
            });
        }
        resp.json::<T>()
            .await
            .map_err(|err| RegistryError::Decode(err.to_string()))
    }

    pub async fn me(&self) -> Result<MeResponse, RegistryError> {
        let path = "/v1/me";
        let resp = self.request(reqwest::Method::GET, path).send().await?;
        Self::json_response(resp, path).await
    }

    pub async fn publish(
        &self,
        namespace: &str,
        name: &str,
        source: Vec<u8>,
        visibility: Option<&str>,
    ) -> Result<PublishResponse, RegistryError> {
        let path = format!("/v1/scripts/{namespace}/{name}");
        let part = reqwest::multipart::Part::bytes(source)
            .file_name(format!("{name}.ruso"))
            .mime_str("text/x-ruso")
            .map_err(|err| RegistryError::Decode(err.to_string()))?;
        let mut form = reqwest::multipart::Form::new().part("source", part);
        if let Some(v) = visibility {
            form = form.text("visibility", v.to_string());
        }
        let resp = self
            .request(reqwest::Method::POST, &path)
            .multipart(form)
            .send()
            .await?;
        Self::json_response(resp, &path).await
    }

    pub async fn show(
        &self,
        namespace: &str,
        name: &str,
        range: Option<&str>,
    ) -> Result<ScriptResponse, RegistryError> {
        let path = format!("/v1/scripts/{namespace}/{name}");
        let mut req = self.request(reqwest::Method::GET, &path);
        if let Some(r) = range {
            req = req.query(&[("range", r)]);
        }
        let resp = req.send().await?;
        Self::json_response(resp, &path).await
    }

    pub async fn download_bytecode(
        &self,
        namespace: &str,
        name: &str,
        version: &str,
    ) -> Result<Vec<u8>, RegistryError> {
        let path = format!("/v1/scripts/{namespace}/{name}/versions/{version}/bytecode");
        let resp = self.request(reqwest::Method::GET, &path).send().await?;
        let status = resp.status();
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(RegistryError::Unauthorized);
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(RegistryError::Http {
                status: status.as_u16(),
                path,
                body,
            });
        }
        Ok(resp.bytes().await?.to_vec())
    }

    pub async fn list_tokens(&self) -> Result<Vec<TokenSummary>, RegistryError> {
        let path = "/v1/tokens";
        let resp = self.request(reqwest::Method::GET, path).send().await?;
        Self::json_response(resp, path).await
    }

    pub async fn create_token(
        &self,
        body: &CreateTokenRequest,
    ) -> Result<TokenCreatedResponse, RegistryError> {
        let path = "/v1/tokens";
        let resp = self
            .request(reqwest::Method::POST, path)
            .json(body)
            .send()
            .await?;
        Self::json_response(resp, path).await
    }

    pub async fn revoke_token(&self, id: &str) -> Result<(), RegistryError> {
        let path = format!("/v1/tokens/{id}");
        let resp = self.request(reqwest::Method::DELETE, &path).send().await?;
        let status = resp.status();
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(RegistryError::Unauthorized);
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(RegistryError::Http {
                status: status.as_u16(),
                path,
                body,
            });
        }
        Ok(())
    }

    pub async fn patch_script(
        &self,
        namespace: &str,
        name: &str,
        body: &PatchScriptRequest,
    ) -> Result<PatchScriptResponse, RegistryError> {
        let path = format!("/v1/scripts/{namespace}/{name}");
        let resp = self
            .request(reqwest::Method::PATCH, &path)
            .json(body)
            .send()
            .await?;
        Self::json_response(resp, &path).await
    }

    pub async fn yank_version(
        &self,
        namespace: &str,
        name: &str,
        version: &str,
        reason: Option<&str>,
    ) -> Result<(), RegistryError> {
        let path = format!("/v1/scripts/{namespace}/{name}/versions/{version}/yank");
        let mut req = self.request(reqwest::Method::POST, &path);
        if let Some(r) = reason {
            req = req.json(&YankRequest {
                reason: Some(r.to_string()),
            });
        }
        Self::no_content_response(req.send().await?, &path).await
    }

    pub async fn unyank_version(
        &self,
        namespace: &str,
        name: &str,
        version: &str,
    ) -> Result<(), RegistryError> {
        let path = format!("/v1/scripts/{namespace}/{name}/versions/{version}/unyank");
        let resp = self.request(reqwest::Method::POST, &path).send().await?;
        Self::no_content_response(resp, &path).await
    }

    /// 204-or-error helper for the yank-family endpoints. Mirrors
    /// `json_response`'s error path but doesn't try to parse a body.
    async fn no_content_response(resp: reqwest::Response, path: &str) -> Result<(), RegistryError> {
        let status = resp.status();
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(RegistryError::Unauthorized);
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(RegistryError::Http {
                status: status.as_u16(),
                path: path.to_string(),
                body,
            });
        }
        Ok(())
    }

    pub async fn search(&self, params: &SearchParams) -> Result<SearchResponse, RegistryError> {
        let path = "/v1/scripts/search";
        let mut query: Vec<(&str, String)> = Vec::new();
        if let Some(q) = &params.q {
            query.push(("q", q.clone()));
        }
        if let Some(sev) = &params.severity {
            query.push(("severity", sev.clone()));
        }
        if let Some(cve) = &params.cve {
            query.push(("cve", cve.clone()));
        }
        if let Some(ns) = &params.namespace {
            query.push(("namespace", ns.clone()));
        }
        if let Some(fam) = &params.family {
            query.push(("family", fam.clone()));
        }
        for tag in &params.tags {
            query.push(("tag", tag.clone()));
        }
        if let Some(page) = params.page {
            query.push(("page", page.to_string()));
        }
        if let Some(pp) = params.per_page {
            query.push(("per_page", pp.to_string()));
        }
        let resp = self
            .request(reqwest::Method::GET, path)
            .query(&query)
            .send()
            .await?;
        Self::json_response(resp, path).await
    }
}

// ───────────────────────────── response types ─────────────────────────────
//
// `dead_code` is suppressed because these mirror the backend's JSON shape
// rather than what the current CLI happens to read — keeping the full
// shape avoids silently dropping fields when a new caller wants them.

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct MeResponse {
    pub id: String,
    pub username: String,
    pub email: String,
    pub github_login: String,
    pub avatar_url: Option<String>,
    pub is_admin: bool,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct PublishResponse {
    pub namespace: String,
    pub name: String,
    pub version: String,
    pub tags: Vec<String>,
    pub visibility: String,
    pub size_bytes: i64,
    pub published_at: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ScriptResponse {
    pub namespace: String,
    pub name: String,
    pub description: Option<String>,
    pub visibility: String,
    pub tags: Vec<String>,
    #[serde(default)]
    pub family: Option<String>,
    pub versions: Vec<VersionSummary>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VersionSummary {
    pub version: String,
    pub size_bytes: i64,
    #[serde(default)]
    pub tags: Vec<String>,
    pub published_at: String,
    pub yanked_at: Option<String>,
    #[serde(default)]
    pub download_count: i64,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct SearchParams {
    pub q: Option<String>,
    pub severity: Option<String>,
    pub cve: Option<String>,
    pub namespace: Option<String>,
    pub family: Option<String>,
    pub tags: Vec<String>,
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SearchResponse {
    pub page: u32,
    pub per_page: u32,
    pub total: i64,
    pub results: Vec<SearchHit>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PatchScriptRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
}

/// PATCH `/v1/scripts/:ns/:name` returns only the editable fields,
/// not the full ScriptResponse (no versions). Mirrors the backend's
/// `PatchResponse` shape.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct PatchScriptResponse {
    pub namespace: String,
    pub name: String,
    pub description: Option<String>,
    pub visibility: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct YankRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct TokenSummary {
    pub id: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub revoked_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateTokenRequest {
    pub name: String,
    pub scopes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct TokenCreatedResponse {
    pub id: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<String>,
    /// Only returned once — the plaintext to hand to the user.
    pub token: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SearchHit {
    pub namespace: String,
    pub name: String,
    pub description: Option<String>,
    pub visibility: String,
    pub severity: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub family: Option<String>,
    #[serde(default)]
    pub cves: Vec<String>,
    pub updated_at: String,
}
