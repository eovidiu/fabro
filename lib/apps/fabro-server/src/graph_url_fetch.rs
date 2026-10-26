//! SSRF-safe fetch of a single workflow file over https, for `POST
//! /api/v1/graph/render-url`.
//!
//! Resolves each hop's host once through an injectable resolver, vets every
//! returned address against a loopback/private/link-local/cloud-metadata
//! blocklist, and pins the connection to the one vetted address (via
//! `fabro_http::resolve_to_addrs`) so a later DNS answer cannot redirect the
//! connection after vetting (DNS rebinding). Proxies are disabled and
//! redirects are followed manually, re-vetted at every hop.

#![expect(
    clippy::disallowed_types,
    reason = "This module parses, vets, and follows reqwest::Url hops directly for SSRF checking and DNS pinning; no URL is logged here."
)]

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use fabro_http::{HeaderValue, HttpClientBuilder, ProxyPolicy, Url, header, redirect};
use tokio::net::lookup_host;
use tokio::time::timeout;

/// Whole-operation budget: every redirect hop and the body read together.
pub(crate) const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
/// Bytes accepted before the fetch is refused as `too_large`: one 3 MiB
/// file is accepted, one byte more is not. Owner decision 2026-10-25,
/// replacing the earlier 1 MiB limit (paired with the 500-node graph
/// limit counted after parsing; see `graph_limits`).
pub(crate) const MAX_BODY_BYTES: usize = 3 * 1024 * 1024;
pub(crate) const MAX_REDIRECTS: u8 = 3;
/// How long the render permit wait and the render subprocess are allowed to
/// run; see `handler::graph_url`.
pub(crate) const RENDER_PERMIT_WAIT: Duration = Duration::from_secs(5);
pub(crate) const RENDER_KILL_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) const RAW_GITHUB_HOST: &str = "raw.githubusercontent.com";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FetchErrorKind {
    InvalidUrl,
    SchemeNotHttps,
    HostNotAllowed,
    Unreachable,
    Timeout,
    HttpStatus(u16),
    TooLarge,
}

#[derive(Debug)]
pub(crate) struct FetchError {
    pub(crate) kind:   FetchErrorKind,
    pub(crate) detail: String,
}

impl FetchError {
    fn new(kind: FetchErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }
}

/// Resolves `(host, port)` to the addresses a caller should vet and connect
/// to. The production resolver is the system/tokio resolver; tests inject
/// one that maps a mock server's hostname to its bound address.
pub(crate) type Resolver = Arc<
    dyn Fn(String, u16) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>>
        + Send
        + Sync,
>;

/// Resolves credentials for `host`, or `None` when `host` is not eligible
/// (only `raw.githubusercontent.com` in production; a test may point this at
/// a mock server's host instead).
pub(crate) type CredentialResolver =
    Arc<dyn Fn(Url) -> Pin<Box<dyn Future<Output = Option<HeaderValue>> + Send>> + Send + Sync>;

fn default_resolver() -> Resolver {
    Arc::new(|host, port| {
        Box::pin(async move {
            lookup_host((host.as_str(), port))
                .await
                .map(Iterator::collect)
        })
    })
}

#[derive(Clone)]
pub(crate) struct FetchPolicy {
    /// Test-only: accepts `http://` in addition to `https://` and exempts
    /// loopback addresses from the block list, since `httpmock` serves
    /// plain HTTP on `127.0.0.1`. Every other blocked range (RFC1918,
    /// link-local, metadata, ...) still refuses, so SSRF-refusal tests stay
    /// meaningful without this flag.
    pub(crate) allow_insecure_loopback: bool,
    pub(crate) resolver:                Resolver,
    pub(crate) fetch_timeout:           Duration,
    pub(crate) max_redirects:           u8,
    pub(crate) max_body_bytes:          usize,
}

impl FetchPolicy {
    pub(crate) fn production() -> Self {
        Self {
            allow_insecure_loopback: false,
            resolver:                default_resolver(),
            fetch_timeout:           FETCH_TIMEOUT,
            max_redirects:           MAX_REDIRECTS,
            max_body_bytes:          MAX_BODY_BYTES,
        }
    }
}

/// Whether `ip` is loopback, unspecified, RFC1918 private, carrier-grade NAT
/// (100.64/10), link-local/metadata (169.254/16, which covers
/// 169.254.169.254), benchmarking (198.18/15), IETF protocol assignments
/// (192.0.0.0/24, which covers DS-Lite and other infrastructure
/// addresses), reserved/future (240/4, which also covers the
/// 255.255.255.255 broadcast address), multicast, broadcast, or an
/// IPv4-mapped form of any of those.
fn is_blocked_ipv4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_loopback()
        || ip.is_unspecified()
        || o[0] == 0
        || o[0] == 10
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 100 && (64..=127).contains(&o[1]))
        || (o[0] == 169 && o[1] == 254)
        || (o[0] == 198 && (18..=19).contains(&o[1]))
        || o[0] >= 240
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
}

/// An IPv4 address embedded in an otherwise-unblocked IPv6 form that must
/// still be vetted against [`is_blocked_ipv4`]: the standard IPv4-mapped
/// form (`::ffff:a.b.c.d`, via [`Ipv6Addr::to_ipv4_mapped`]), the
/// IPv4-translated form (`::ffff:0:a.b.c.d`, RFC 8215, `::ffff:0:0:0/96`),
/// the deprecated IPv4-compatible form (`::a.b.c.d`, RFC 4291 §2.5.5.1),
/// the NAT64 well-known prefix (`64:ff9b::/96`, RFC 6052) a DNS64 resolver
/// can hand back for any public IPv4 destination, including blocked ones,
/// and 6to4 (`2002::/16`, RFC 3056), which carries the IPv4 address in
/// bits 16-48.
fn embedded_ipv4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return Some(v4);
    }
    let seg = ip.segments();
    let is_ipv4_compatible = seg[0] == 0
        && seg[1] == 0
        && seg[2] == 0
        && seg[3] == 0
        && seg[4] == 0
        && seg[5] == 0
        && (seg[6], seg[7]) != (0, 0)
        && (seg[6], seg[7]) != (0, 1);
    let is_nat64_well_known = seg[0] == 0x0064
        && seg[1] == 0xff9b
        && seg[2] == 0
        && seg[3] == 0
        && seg[4] == 0
        && seg[5] == 0;
    let is_ipv4_translated =
        seg[0] == 0 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0 && seg[4] == 0xffff && seg[5] == 0;
    if is_ipv4_compatible || is_nat64_well_known || is_ipv4_translated {
        return Some(Ipv4Addr::new(
            (seg[6] >> 8) as u8,
            (seg[6] & 0xff) as u8,
            (seg[7] >> 8) as u8,
            (seg[7] & 0xff) as u8,
        ));
    }
    if seg[0] == 0x2002 {
        return Some(Ipv4Addr::new(
            (seg[1] >> 8) as u8,
            (seg[1] & 0xff) as u8,
            (seg[2] >> 8) as u8,
            (seg[2] & 0xff) as u8,
        ));
    }
    None
}

/// Whether `ip` is loopback (`::1`), unspecified, multicast, unique local
/// (`fc00::/7`), link-local (`fe80::/10`), the deprecated site-local
/// range (`fec0::/10`, RFC 3879: formally deprecated but still routed
/// within some private networks, so it is blocked outright alongside
/// its link-local sibling rather than trusted as public), the NAT64
/// local-use prefix (`64:ff9b:1::/48`, blocked outright: legitimate
/// public traffic never arrives through it), Teredo (`2001::/32`, RFC
/// 4380, blocked outright: it tunnels through potentially-unvetted
/// relay infrastructure, so its embedded client address cannot be
/// trusted), or embeds (per [`embedded_ipv4`]) an IPv4 address
/// `is_blocked_ipv4` would refuse.
fn is_blocked_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = embedded_ipv4(ip) {
        return is_blocked_ipv4(v4);
    }
    let seg = ip.segments();
    if seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2] == 0x0001 {
        return true;
    }
    if seg[0] == 0x2001 && seg[1] == 0 {
        return true;
    }
    let seg0 = seg[0];
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (seg0 & 0xfe00) == 0xfc00
        || (seg0 & 0xffc0) == 0xfe80
        || (seg0 & 0xffc0) == 0xfec0
}

fn is_blocked(addr: IpAddr, allow_loopback: bool) -> bool {
    if allow_loopback && addr.is_loopback() {
        return false;
    }
    match addr {
        IpAddr::V4(v4) => is_blocked_ipv4(v4),
        IpAddr::V6(v6) => is_blocked_ipv6(v6),
    }
}

fn validate_hop_url(url: &Url, policy: &FetchPolicy) -> Result<(), FetchError> {
    let scheme_ok =
        url.scheme() == "https" || (policy.allow_insecure_loopback && url.scheme() == "http");
    if !scheme_ok {
        return Err(FetchError::new(
            FetchErrorKind::SchemeNotHttps,
            format!("unsupported scheme: {}", url.scheme()),
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(FetchError::new(
            FetchErrorKind::InvalidUrl,
            "URL must not carry userinfo",
        ));
    }
    if url.host_str().is_none() {
        return Err(FetchError::new(
            FetchErrorKind::InvalidUrl,
            "URL has no host",
        ));
    }
    Ok(())
}

fn parse_start_url(raw: &str) -> Result<Url, FetchError> {
    Url::parse(raw).map_err(|err| FetchError::new(FetchErrorKind::InvalidUrl, err.to_string()))
}

/// Remove the `token` query parameter GitHub's UI appends to raw-file links
/// (a short-lived, user-scoped token). Fabro attaches its own GitHub
/// credentials instead, so a stray `token` is dropped rather than sent
/// upstream or allowed to collide with Fabro's `Authorization` header.
fn strip_token_query_param(url: &mut Url) {
    if url.query().is_none_or(|query| !query.contains("token=")) {
        return;
    }
    let kept: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(key, _)| key != "token")
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    if kept.is_empty() {
        url.set_query(None);
    } else {
        url.query_pairs_mut().clear().extend_pairs(&kept);
    }
}

/// `(owner, repo)` for a
/// `raw.githubusercontent.com/<owner>/<repo>/<ref>/<path>` URL, or `None` for
/// any other host (including `github.com` blob URLs and GitHub Enterprise
/// hosts, which get no credentials in v1).
pub(crate) fn raw_github_owner_repo(url: &Url) -> Option<(String, String)> {
    if !url
        .host_str()
        .is_some_and(|host| host.eq_ignore_ascii_case(RAW_GITHUB_HOST))
    {
        return None;
    }
    let mut segments = url.path_segments()?;
    let owner = segments.next()?.to_string();
    let repo = segments.next()?.to_string();
    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    Some((owner, repo))
}

/// The size-cap check `read_body_capped` applies to each chunk as it
/// arrives, factored out as a pure function so it can be unit-tested
/// against a synthetic chunk sequence with no declared length at all
/// (AC5: the cap is enforced by counting bytes actually read, never by
/// trusting any `Content-Length` the server claims).
fn apply_body_cap(body: &mut Vec<u8>, chunk: &[u8], max_bytes: usize) -> Result<(), FetchError> {
    body.extend_from_slice(chunk);
    if body.len() > max_bytes {
        return Err(FetchError::new(
            FetchErrorKind::TooLarge,
            "downloaded file exceeds the size limit",
        ));
    }
    Ok(())
}

async fn read_body_capped(
    mut response: fabro_http::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, FetchError> {
    let mut body = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => apply_body_cap(&mut body, &chunk, max_bytes)?,
            Ok(None) => return Ok(body),
            Err(err) => {
                return Err(FetchError::new(
                    FetchErrorKind::Unreachable,
                    err.to_string(),
                ));
            }
        }
    }
}

/// Fetch `start_url`, following up to `policy.max_redirects` https redirects,
/// vetting every hop's resolved address, and capping the body at
/// `policy.max_body_bytes`. `credentials` is asked for an `Authorization`
/// header value each time the current hop's host changes; the header is
/// dropped on a cross-host redirect.
pub(crate) async fn fetch_workflow(
    start_url: &str,
    policy: &FetchPolicy,
    credentials: &CredentialResolver,
) -> Result<Vec<u8>, FetchError> {
    match timeout(
        policy.fetch_timeout,
        fetch_workflow_inner(start_url, policy, credentials),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(FetchError::new(
            FetchErrorKind::Timeout,
            "fetching the workflow timed out",
        )),
    }
}

async fn fetch_workflow_inner(
    start_url: &str,
    policy: &FetchPolicy,
    credentials: &CredentialResolver,
) -> Result<Vec<u8>, FetchError> {
    let mut current = parse_start_url(start_url)?;
    validate_hop_url(&current, policy)?;

    let mut auth: Option<(String, HeaderValue)> = None;

    for hop in 0..=policy.max_redirects {
        let host = current
            .host_str()
            .ok_or_else(|| FetchError::new(FetchErrorKind::InvalidUrl, "URL has no host"))?;
        let host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host)
            .to_string();
        if raw_github_owner_repo(&current).is_some() {
            strip_token_query_param(&mut current);
        }

        let port = current.port_or_known_default().unwrap_or(443);
        let addrs = (policy.resolver)(host.clone(), port)
            .await
            .map_err(|err| FetchError::new(FetchErrorKind::Unreachable, err.to_string()))?;
        let vetted = addrs
            .into_iter()
            .find(|addr| !is_blocked(addr.ip(), policy.allow_insecure_loopback));
        let Some(addr) = vetted else {
            return Err(FetchError::new(
                FetchErrorKind::HostNotAllowed,
                format!("{host} has no allowed address"),
            ));
        };

        if auth
            .as_ref()
            .is_none_or(|(auth_host, _)| *auth_host != host)
        {
            auth = credentials(current.clone())
                .await
                .map(|header_value| (host.clone(), header_value));
        }

        let client = HttpClientBuilder::new()
            .proxy_policy(ProxyPolicy::Disabled)
            .redirect(redirect::Policy::none())
            .dns_resolver(fabro_http::resolve_to_addrs(vec![addr]))
            .build()
            .map_err(|err| FetchError::new(FetchErrorKind::Unreachable, err.to_string()))?;

        let mut request = client.get(current.clone());
        if let Some((auth_host, header_value)) = &auth {
            if auth_host == &host {
                request = request.header(header::AUTHORIZATION, header_value.clone());
            }
        }

        let response = request
            .send()
            .await
            .map_err(|err| FetchError::new(FetchErrorKind::Unreachable, err.to_string()))?;

        let status = response.status();
        if status.is_redirection() {
            if hop == policy.max_redirects {
                return Err(FetchError::new(
                    FetchErrorKind::HostNotAllowed,
                    "too many redirects",
                ));
            }
            let location = response
                .headers()
                .get(header::LOCATION)
                .ok_or_else(|| {
                    FetchError::new(
                        FetchErrorKind::Unreachable,
                        "redirect with no Location header",
                    )
                })?
                .to_str()
                .map_err(|_| {
                    FetchError::new(
                        FetchErrorKind::InvalidUrl,
                        "redirect Location header is not valid ASCII",
                    )
                })?;
            let next = current
                .join(location)
                .map_err(|err| FetchError::new(FetchErrorKind::InvalidUrl, err.to_string()))?;
            validate_hop_url(&next, policy)?;
            if next.host_str() != Some(host.as_str()) {
                auth = None;
            }
            current = next;
            continue;
        }

        if !status.is_success() {
            return Err(FetchError::new(
                FetchErrorKind::HttpStatus(status.as_u16()),
                format!("upstream returned {status}"),
            ));
        }

        return read_body_capped(response, policy.max_body_bytes).await;
    }

    Err(FetchError::new(
        FetchErrorKind::HostNotAllowed,
        "too many redirects",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_body_cap_stops_at_the_boundary_with_no_declared_length() {
        // AC5: simulates a chunked-transfer, no-Content-Length upstream
        // body (small, irregular chunk sizes, no total ever declared) and
        // proves the cap is enforced purely by counting bytes consumed:
        // the 3 MiB boundary is accepted, one byte more is refused, and
        // the reader never accumulates past a single chunk beyond it.
        let max_bytes = 3 * 1024 * 1024;
        let chunk = vec![b'a'; 64 * 1024]; // 64 KiB per chunk, like a real stream

        // Exactly at the cap: every chunk is accepted.
        let mut body = Vec::new();
        for _ in 0..(max_bytes / chunk.len()) {
            apply_body_cap(&mut body, &chunk, max_bytes).expect("should stay within the cap");
        }
        assert_eq!(body.len(), max_bytes);

        // One more byte (a tiny final chunk) pushes it over: refused, and
        // the body is never grown past this one small over-the-cap chunk
        // — i.e. reading stopped at byte max_bytes + 1, not after
        // draining some larger remaining stream.
        let err = apply_body_cap(&mut body, b"x", max_bytes).expect_err("should be refused");
        assert_eq!(err.kind, FetchErrorKind::TooLarge);
        assert_eq!(body.len(), max_bytes + 1);
    }

    #[test]
    fn graph_url_ip_policy_table() {
        let blocked: &[&str] = &[
            "127.0.0.1",
            "0.0.0.0",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "100.64.0.1",
            "100.127.255.255",
            "169.254.169.254", // cloud metadata
            "169.254.0.1",
            "224.0.0.1",       // multicast
            "255.255.255.255", // broadcast
            "::1",
            "::",
            "fe80::1",
            "ff02::1",
            "fc00::1",
            "fd00::1",
            "fec0::1", // deprecated site-local (RFC 3879), still routed on some private networks
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            // NAT64 well-known prefix (RFC 6052): embedded IPv4 is private/metadata.
            "64:ff9b::a9fe:a9fe", // embeds 169.254.169.254
            "64:ff9b::a00:1",     // embeds 10.0.0.1
            // IPv4-compatible (deprecated, RFC 4291 2.5.5.1): embeds a private address.
            "::a9fe:a9fe",
            // NAT64 local-use prefix: blocked outright.
            "64:ff9b:1::1",
            // Benchmarking (198.18.0.0/15) and reserved/future (240.0.0.0/4).
            "198.18.0.1",
            "198.19.255.255",
            "240.0.0.1",
            // IETF protocol assignments (192.0.0.0/24, e.g. DS-Lite).
            "192.0.0.1",
            // Documentation/TEST-NET ranges (RFC 5737).
            "192.0.2.1",
            "203.0.113.1",
            // 6to4 (2002::/16): embeds 10.0.0.1 in bits 16-48.
            "2002:a00:1::",
            // Teredo (2001::/32): blocked outright.
            "2001::1",
            // IPv4-translated (RFC 8215, ::ffff:0:0:0/96): embeds a private address.
            "::ffff:0:a9fe:a9fe",
        ];
        for ip in blocked {
            let addr: IpAddr = ip.parse().unwrap();
            assert!(is_blocked(addr, false), "{ip} should be blocked");
        }

        let allowed: &[&str] = &[
            "93.184.216.34",
            "1.1.1.1",
            "2606:4700:4700::1111",
            "64:ff9b::101:101", // NAT64-of-public (1.1.1.1)
            "198.20.0.1",       // just past 198.18.0.0/15
        ];
        for ip in allowed {
            let addr: IpAddr = ip.parse().unwrap();
            assert!(!is_blocked(addr, false), "{ip} should be allowed");
        }
    }

    #[test]
    fn graph_url_allow_insecure_loopback_only_exempts_loopback() {
        assert!(!is_blocked("127.0.0.1".parse().unwrap(), true));
        assert!(!is_blocked("::1".parse().unwrap(), true));
        assert!(is_blocked("10.0.0.1".parse().unwrap(), true));
        assert!(is_blocked("169.254.169.254".parse().unwrap(), true));
    }

    #[test]
    fn graph_url_github_raw_slug_parsing() {
        let url = Url::parse(
            "https://raw.githubusercontent.com/acme/widgets/main/.fabro/workflows/x/workflow.fabro",
        )
        .unwrap();
        assert_eq!(
            raw_github_owner_repo(&url),
            Some(("acme".to_string(), "widgets".to_string()))
        );

        let blob = Url::parse("https://github.com/acme/widgets/blob/main/workflow.fabro").unwrap();
        assert_eq!(raw_github_owner_repo(&blob), None);

        let ghe = Url::parse("https://raw.ghe.acme.internal/acme/widgets/main/x").unwrap();
        assert_eq!(raw_github_owner_repo(&ghe), None);

        let other = Url::parse("https://example.com/acme/widgets/main/x").unwrap();
        assert_eq!(raw_github_owner_repo(&other), None);
    }

    #[test]
    fn graph_url_token_query_is_stripped() {
        let mut url = Url::parse(
            "https://raw.githubusercontent.com/acme/widgets/main/x?token=GHSAT0AAAA&ref=main",
        )
        .unwrap();
        strip_token_query_param(&mut url);
        assert_eq!(url.query(), Some("ref=main"));

        let mut only_token =
            Url::parse("https://raw.githubusercontent.com/acme/widgets/main/x?token=abc").unwrap();
        strip_token_query_param(&mut only_token);
        assert_eq!(only_token.query(), None);

        let mut no_token =
            Url::parse("https://raw.githubusercontent.com/acme/widgets/main/x?ref=main").unwrap();
        strip_token_query_param(&mut no_token);
        assert_eq!(no_token.query(), Some("ref=main"));
    }

    #[test]
    fn graph_url_production_policy_constants() {
        let policy = FetchPolicy::production();
        assert_eq!(policy.fetch_timeout, Duration::from_secs(10));
        assert_eq!(policy.max_redirects, 3);
        assert_eq!(policy.max_body_bytes, 3 * 1024 * 1024);
        assert!(!policy.allow_insecure_loopback);
        assert_eq!(RENDER_PERMIT_WAIT, Duration::from_secs(5));
        assert_eq!(RENDER_KILL_TIMEOUT, Duration::from_secs(10));
    }
}
