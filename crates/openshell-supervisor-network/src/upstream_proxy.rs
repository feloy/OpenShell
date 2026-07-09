// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Upstream corporate proxy chaining for the sandbox egress proxy.
//!
//! In proxy-required enterprise networks (issue #1792) the supervisor cannot
//! dial policy-approved destinations directly: all outbound traffic must go
//! through a corporate forward proxy. This module reads the standard
//! `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` / `NO_PROXY` variables from the
//! supervisor's **own** environment (the workload child's proxy variables are
//! rewritten separately to point at the local policy proxy) and chains
//! approved connections through the corporate proxy with HTTP CONNECT.
//!
//! Scope and invariants:
//! - `http://` and `https://` proxy URLs are supported; SOCKS proxies are
//!   ignored with a warning. For `https://` proxies the supervisor opens a
//!   TLS connection to the proxy first and runs the CONNECT handshake inside
//!   it, verifying the proxy certificate against the built-in and system
//!   roots plus an optional corporate CA bundle named by the
//!   `OPENSHELL_PROXY_CA_BUNDLE` environment variable (path to a PEM file).
//! - The same CA bundle is also folded into the sandbox trust bundle and the
//!   L7 upstream verification store at startup (see `run.rs`): a
//!   TLS-intercepting corporate proxy re-signs tunneled server certificates
//!   with its CA, so trusting it only for the proxy-listener handshake would
//!   make every intercepted upstream handshake fail.
//! - Policy evaluation, DNS resolution, and SSRF checks run exactly as in the
//!   direct-dial path; the corporate proxy only replaces the final TCP dial.
//! - `NO_PROXY` decides which destinations bypass the corporate proxy and
//!   keep dialing directly (cluster-internal services, host gateway, etc.).
//!   Loopback destinations always bypass the proxy.

use std::io::{Error as IoError, ErrorKind};
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use base64::Engine as _;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, warn};

/// Upper bound on the corporate proxy's CONNECT response header block.
const MAX_CONNECT_RESPONSE_BYTES: usize = 8 * 1024;

/// End-to-end budget for dialing the corporate proxy and completing the
/// CONNECT handshake.
const CONNECT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Which proxy variable applies to a destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamScheme {
    /// TLS-bound tunnels (client issued CONNECT): `HTTPS_PROXY`.
    Https,
    /// Plain HTTP forward-proxy requests: `HTTP_PROXY`.
    Http,
}

/// A parsed corporate proxy endpoint.
#[derive(Clone)]
pub struct ProxyEndpoint {
    host: String,
    port: u16,
    /// Pre-computed `Basic <base64>` header value from URL userinfo.
    /// Never logged.
    proxy_authorization: Option<String>,
    /// TLS client config for `https://` proxies; `None` for plain `http://`.
    /// The connection to the proxy is wrapped in TLS before the CONNECT
    /// handshake.
    tls: Option<Arc<ClientConfig>>,
}

impl ProxyEndpoint {
    /// `host:port` label for logs. Excludes credentials.
    #[must_use]
    pub fn display_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// `scheme://host:port` label for startup logging. Excludes credentials.
    fn display_url(&self) -> String {
        let scheme = if self.tls.is_some() { "https" } else { "http" };
        format!("{scheme}://{}:{}", self.host, self.port)
    }
}

impl std::fmt::Debug for ProxyEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyEndpoint")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("proxy_authorization", &self.proxy_authorization.is_some())
            .field("tls", &self.tls.is_some())
            .finish()
    }
}

/// One parsed `NO_PROXY` entry.
#[derive(Debug, Clone)]
enum NoProxyEntry {
    /// `*` — bypass the proxy for every destination.
    Wildcard,
    /// Domain suffix match: `corp.com` matches `corp.com` and `x.corp.com`.
    Domain(String),
    /// Exact IP literal match.
    Ip(IpAddr),
    /// CIDR match against IP-literal destination hosts.
    Cidr(ipnet::IpNet),
}

/// Parsed `NO_PROXY` list.
#[derive(Debug, Clone, Default)]
struct NoProxy {
    entries: Vec<NoProxyEntry>,
}

impl NoProxy {
    fn parse(raw: &str) -> Self {
        let mut entries = Vec::new();
        for item in raw.split(',') {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            if item == "*" {
                entries.push(NoProxyEntry::Wildcard);
                continue;
            }
            if let Ok(net) = item.parse::<ipnet::IpNet>() {
                entries.push(NoProxyEntry::Cidr(net));
                continue;
            }
            if let Ok(ip) = item.trim_matches(['[', ']']).parse::<IpAddr>() {
                entries.push(NoProxyEntry::Ip(ip));
                continue;
            }
            // Domain entry. Strip a `:port` qualifier (ports are ignored),
            // then any leading `*.` or `.` so `.corp.com`, `*.corp.com`, and
            // `corp.com` all behave identically.
            let name = item.rsplit_once(':').map_or(item, |(name, port)| {
                if port.chars().all(|c| c.is_ascii_digit()) {
                    name
                } else {
                    item
                }
            });
            let name = name
                .strip_prefix("*.")
                .or_else(|| name.strip_prefix('.'))
                .unwrap_or(name)
                .to_ascii_lowercase();
            if !name.is_empty() {
                entries.push(NoProxyEntry::Domain(name));
            }
        }
        Self { entries }
    }

    /// Whether `host` (lowercase hostname or IP literal) must bypass the
    /// corporate proxy. Loopback destinations always match.
    fn matches(&self, host: &str) -> bool {
        let host_ip = host.trim_matches(['[', ']']).parse::<IpAddr>().ok();
        if host == "localhost" || host_ip.is_some_and(|ip| ip.is_loopback()) {
            return true;
        }
        self.entries.iter().any(|entry| match entry {
            NoProxyEntry::Wildcard => true,
            NoProxyEntry::Domain(suffix) => {
                host == suffix
                    || host
                        .strip_suffix(suffix)
                        .is_some_and(|prefix| prefix.ends_with('.'))
            }
            NoProxyEntry::Ip(ip) => host_ip == Some(*ip),
            NoProxyEntry::Cidr(net) => host_ip.is_some_and(|ip| net.contains(&ip)),
        })
    }
}

/// Corporate proxy configuration read from the supervisor's environment.
#[derive(Debug, Clone)]
pub struct UpstreamProxyConfig {
    https: Option<ProxyEndpoint>,
    http: Option<ProxyEndpoint>,
    no_proxy: NoProxy,
}

impl UpstreamProxyConfig {
    /// Read `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` / `NO_PROXY` (lowercase
    /// variants take precedence) from the process environment. Returns `None`
    /// when no usable proxy is configured.
    #[must_use]
    pub fn from_env() -> Option<Self> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Option<Self> {
        let var = |upper: &str, lower: &str| {
            lookup(lower)
                .or_else(|| lookup(upper))
                .filter(|v| !v.trim().is_empty())
        };
        let all = var("ALL_PROXY", "all_proxy");
        // TLS client config for `https://` proxy URLs, built at most once and
        // shared by both endpoints. Root store: built-in Mozilla roots +
        // system bundle + the optional corporate CA bundle file named by
        // `OPENSHELL_PROXY_CA_BUNDLE`.
        let tls_config_cell = std::cell::OnceCell::new();
        let tls_config = || -> Arc<ClientConfig> {
            tls_config_cell
                .get_or_init(|| {
                    build_proxy_tls_config(proxy_ca_bundle_pem_with(&lookup).as_deref())
                })
                .clone()
        };
        let https = var("HTTPS_PROXY", "https_proxy")
            .or_else(|| all.clone())
            .and_then(|url| parse_proxy_url(&url, "HTTPS_PROXY", &tls_config));
        let http = var("HTTP_PROXY", "http_proxy")
            .or(all)
            .and_then(|url| parse_proxy_url(&url, "HTTP_PROXY", &tls_config));
        if https.is_none() && http.is_none() {
            return None;
        }
        let no_proxy = NoProxy::parse(&var("NO_PROXY", "no_proxy").unwrap_or_default());
        Some(Self {
            https,
            http,
            no_proxy,
        })
    }

    /// The corporate proxy to use for `host`, or `None` when the destination
    /// must be dialed directly.
    #[must_use]
    pub fn proxy_for(&self, scheme: UpstreamScheme, host: &str) -> Option<&ProxyEndpoint> {
        if self.no_proxy.matches(host) {
            return None;
        }
        match scheme {
            UpstreamScheme::Https => self.https.as_ref(),
            UpstreamScheme::Http => self.http.as_ref(),
        }
    }

    /// Credential-free summary for startup logging.
    #[must_use]
    pub fn summary(&self) -> String {
        let fmt = |ep: Option<&ProxyEndpoint>| {
            ep.map_or_else(|| "-".to_string(), ProxyEndpoint::display_url)
        };
        format!(
            "https_proxy={} http_proxy={} no_proxy_entries={}",
            fmt(self.https.as_ref()),
            fmt(self.http.as_ref()),
            self.no_proxy.entries.len()
        )
    }
}

/// Read the corporate proxy CA bundle PEM named by the
/// `OPENSHELL_PROXY_CA_BUNDLE` environment variable, if set and readable.
///
/// A TLS-intercepting corporate proxy signs both its own listener
/// certificate and the re-signed certificates of tunneled destinations with
/// this CA, so callers use the bundle for proxy-listener TLS (`https://`
/// proxy URLs) and for upstream certificate verification behind the proxy.
#[must_use]
pub fn proxy_ca_bundle_pem() -> Option<String> {
    proxy_ca_bundle_pem_with(&|name| std::env::var(name).ok())
}

fn proxy_ca_bundle_pem_with(lookup: &dyn Fn(&str) -> Option<String>) -> Option<String> {
    let ca_var = openshell_core::sandbox_env::PROXY_CA_BUNDLE;
    let path = lookup(ca_var).map(|path| path.trim().to_string())?;
    if path.is_empty() {
        return None;
    }
    match std::fs::read_to_string(&path) {
        Ok(pem) => Some(pem),
        Err(err) => {
            warn!(
                "failed to read {ca_var} '{path}': {err}; \
                 the corporate proxy CA will not be trusted"
            );
            None
        }
    }
}

/// Parse an `http(s)://[user:pass@]host[:port]` proxy URL. Unsupported
/// schemes (SOCKS proxies) are rejected with a warning. For `https://`
/// proxies, `tls_config` supplies the shared TLS client configuration.
fn parse_proxy_url(
    raw: &str,
    var_name: &str,
    tls_config: &dyn Fn() -> Arc<ClientConfig>,
) -> Option<ProxyEndpoint> {
    let raw = raw.trim();
    let (tls, rest) = match raw.split_once("://") {
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case("http") => (false, rest),
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case("https") => (true, rest),
        Some((scheme, _)) => {
            warn!(
                "{var_name} uses unsupported proxy scheme '{scheme}' \
                 (only http:// and https:// proxies are supported); ignoring"
            );
            return None;
        }
        None => (false, raw),
    };
    // Drop any path component.
    let rest = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let (userinfo, authority) = match rest.rsplit_once('@') {
        Some((userinfo, authority)) => (Some(userinfo), authority),
        None => (None, rest),
    };
    let default_port = if tls { 443 } else { 80 };
    let Some((host, port)) = split_host_port(authority, default_port) else {
        warn!("{var_name} has an invalid proxy address '{authority}'; ignoring");
        return None;
    };
    let proxy_authorization = userinfo.map(|userinfo| {
        let (user, pass) = userinfo.split_once(':').unwrap_or((userinfo, ""));
        let credentials = format!("{}:{}", percent_decode(user), percent_decode(pass));
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(credentials)
        )
    });
    Some(ProxyEndpoint {
        host,
        port,
        proxy_authorization,
        tls: tls.then(tls_config),
    })
}

/// Build the TLS client config used to connect to an `https://` corporate
/// proxy: built-in Mozilla roots + system CA bundle + the optional corporate
/// CA bundle PEM.
fn build_proxy_tls_config(corporate_ca_pem: Option<&str>) -> Arc<ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let system_bundle = crate::l7::tls::read_system_ca_bundle();
    crate::l7::tls::load_pem_certs_into_store(&mut root_store, &system_bundle);

    if let Some(pem) = corporate_ca_pem {
        let (added, ignored) = crate::l7::tls::load_pem_certs_into_store(&mut root_store, pem);
        if added == 0 {
            warn!(
                "OPENSHELL_PROXY_CA_BUNDLE contained no usable certificates; \
                 verifying the upstream proxy against built-in and system roots only"
            );
        } else {
            debug!(
                added,
                ignored, "loaded corporate CA certificates for upstream proxy TLS"
            );
        }
    }

    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

/// Split `host[:port]` (with optional `[v6]` brackets), defaulting to
/// `default_port` (80 for `http://` proxies, 443 for `https://`).
fn split_host_port(authority: &str, default_port: u16) -> Option<(String, u16)> {
    if authority.is_empty() {
        return None;
    }
    if let Some(v6_end) = authority.find(']') {
        if !authority.starts_with('[') {
            return None;
        }
        let host = authority[1..v6_end].to_string();
        let port = match authority[v6_end + 1..].strip_prefix(':') {
            Some(port) => port.parse().ok()?,
            None if authority[v6_end + 1..].is_empty() => default_port,
            None => return None,
        };
        return Some((host, port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => Some((host.to_string(), port.parse().ok()?)),
        Some(_) => None, // bare IPv6 without brackets is ambiguous
        None => Some((authority.to_string(), default_port)),
    }
}

/// Minimal percent-decoder for URL userinfo.
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            )
        {
            #[allow(clippy::cast_possible_truncation)]
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A connected upstream byte stream: either a plain TCP connection or a
/// stream tunneled inside a TLS session to an `https://` corporate proxy.
///
/// Direct dials and `http://` proxy tunnels are `Plain`; only the transport
/// differs, so both variants behave as transparent byte pipes.
#[derive(Debug)]
pub enum UpstreamStream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl From<TcpStream> for UpstreamStream {
    fn from(stream: TcpStream) -> Self {
        Self::Plain(stream)
    }
}

impl AsyncRead for UpstreamStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for UpstreamStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Plain(s) => s.is_write_vectored(),
            Self::Tls(s) => s.is_write_vectored(),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Open a tunnel to `host:port` through the corporate proxy with HTTP CONNECT.
///
/// For `https://` proxies the proxy connection is wrapped in TLS (verifying
/// the proxy certificate against the configured roots) before the CONNECT
/// handshake. Returns the connected stream once the proxy answers 200; after
/// that the stream is a transparent byte pipe to the destination.
///
/// The destination hostname (not a locally resolved IP) is sent in the
/// CONNECT target so hostname-filtering proxies keep working; local DNS
/// resolution and SSRF validation must already have happened at the call
/// site.
///
/// # Errors
///
/// Returns an error when the proxy is unreachable, TLS verification of the
/// proxy fails, the handshake times out, or the proxy answers with a non-200
/// status.
pub async fn connect_via(
    endpoint: &ProxyEndpoint,
    host: &str,
    port: u16,
) -> std::io::Result<UpstreamStream> {
    tokio::time::timeout(
        CONNECT_HANDSHAKE_TIMEOUT,
        connect_via_inner(endpoint, host, port),
    )
    .await
    .map_err(|_| {
        IoError::new(
            ErrorKind::TimedOut,
            format!(
                "upstream proxy {} CONNECT handshake timed out",
                endpoint.display_addr()
            ),
        )
    })?
}

async fn connect_via_inner(
    endpoint: &ProxyEndpoint,
    host: &str,
    port: u16,
) -> std::io::Result<UpstreamStream> {
    let tcp = TcpStream::connect((endpoint.host.as_str(), endpoint.port)).await?;
    let mut stream = match &endpoint.tls {
        Some(config) => {
            let server_name = ServerName::try_from(endpoint.host.clone()).map_err(|err| {
                IoError::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "upstream proxy host '{}' is not a valid TLS server name: {err}",
                        endpoint.host
                    ),
                )
            })?;
            let connector = TlsConnector::from(Arc::clone(config));
            let tls = connector.connect(server_name, tcp).await.map_err(|err| {
                IoError::new(
                    err.kind(),
                    format!(
                        "TLS handshake with upstream proxy {} failed: {err}",
                        endpoint.display_addr()
                    ),
                )
            })?;
            UpstreamStream::Tls(Box::new(tls))
        }
        None => UpstreamStream::Plain(tcp),
    };
    connect_handshake(&mut stream, endpoint, host, port).await?;
    Ok(stream)
}

/// Send the CONNECT request and read the proxy's response on an established
/// (possibly TLS-wrapped) proxy connection.
async fn connect_handshake<S>(
    stream: &mut S,
    endpoint: &ProxyEndpoint,
    host: &str,
    port: u16,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let target = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let mut request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some(auth) = &endpoint.proxy_authorization {
        request.push_str("Proxy-Authorization: ");
        request.push_str(auth);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;

    // Read the proxy's response header block.
    let mut buf = vec![0u8; MAX_CONNECT_RESPONSE_BYTES];
    let mut used = 0;
    loop {
        if used == buf.len() {
            return Err(IoError::other(format!(
                "upstream proxy {} CONNECT response headers exceed {MAX_CONNECT_RESPONSE_BYTES} bytes",
                endpoint.display_addr()
            )));
        }
        let n = stream.read(&mut buf[used..]).await?;
        if n == 0 {
            return Err(IoError::new(
                ErrorKind::UnexpectedEof,
                format!(
                    "upstream proxy {} closed the connection during CONNECT",
                    endpoint.display_addr()
                ),
            ));
        }
        used += n;
        if buf[..used].windows(4).any(|win| win == b"\r\n\r\n") {
            break;
        }
    }

    let response = String::from_utf8_lossy(&buf[..used]);
    let status_line = response.lines().next().unwrap_or_default();
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok());
    match status_code {
        Some(200) => {
            debug!(
                proxy = %endpoint.display_addr(),
                target = %target,
                "upstream proxy CONNECT tunnel established"
            );
            Ok(())
        }
        Some(code) => Err(IoError::other(format!(
            "upstream proxy {} refused CONNECT to {target}: HTTP {code}",
            endpoint.display_addr()
        ))),
        None => Err(IoError::new(
            ErrorKind::InvalidData,
            format!(
                "upstream proxy {} sent a malformed CONNECT response",
                endpoint.display_addr()
            ),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_from(pairs: &[(&str, &str)]) -> Option<UpstreamProxyConfig> {
        UpstreamProxyConfig::from_lookup(|name| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| (*v).to_string())
        })
    }

    #[test]
    fn no_env_yields_none() {
        assert!(config_from(&[]).is_none());
    }

    #[test]
    fn empty_values_yield_none() {
        assert!(config_from(&[("HTTPS_PROXY", "  "), ("HTTP_PROXY", "")]).is_none());
    }

    #[test]
    fn https_proxy_parsed_with_port() {
        let cfg = config_from(&[("HTTPS_PROXY", "http://proxy.corp.com:8080")]).unwrap();
        let ep = cfg
            .proxy_for(UpstreamScheme::Https, "api.stripe.com")
            .unwrap();
        assert_eq!(ep.display_addr(), "proxy.corp.com:8080");
        assert!(ep.proxy_authorization.is_none());
        assert!(
            cfg.proxy_for(UpstreamScheme::Http, "api.stripe.com")
                .is_none()
        );
    }

    #[test]
    fn lowercase_takes_precedence() {
        let cfg = config_from(&[
            ("HTTPS_PROXY", "http://upper:1111"),
            ("https_proxy", "http://lower:2222"),
        ])
        .unwrap();
        let ep = cfg.proxy_for(UpstreamScheme::Https, "example.com").unwrap();
        assert_eq!(ep.display_addr(), "lower:2222");
    }

    #[test]
    fn all_proxy_fills_both_schemes() {
        let cfg = config_from(&[("ALL_PROXY", "http://proxy:3128")]).unwrap();
        assert!(
            cfg.proxy_for(UpstreamScheme::Https, "example.com")
                .is_some()
        );
        assert!(cfg.proxy_for(UpstreamScheme::Http, "example.com").is_some());
    }

    #[test]
    fn scheme_defaults_to_http_and_port_defaults_to_80() {
        let cfg = config_from(&[("HTTP_PROXY", "proxy.corp.com")]).unwrap();
        let ep = cfg.proxy_for(UpstreamScheme::Http, "example.com").unwrap();
        assert_eq!(ep.display_addr(), "proxy.corp.com:80");
    }

    #[test]
    fn socks_proxies_rejected() {
        assert!(config_from(&[("HTTPS_PROXY", "socks5://proxy:1080")]).is_none());
    }

    #[test]
    fn https_proxy_scheme_enables_tls_and_defaults_to_port_443() {
        let cfg = config_from(&[("HTTPS_PROXY", "https://proxy.corp.com")]).unwrap();
        let ep = cfg.proxy_for(UpstreamScheme::Https, "example.com").unwrap();
        assert_eq!(ep.display_addr(), "proxy.corp.com:443");
        assert!(ep.tls.is_some());
        assert_eq!(
            cfg.summary(),
            "https_proxy=https://proxy.corp.com:443 http_proxy=- no_proxy_entries=0"
        );
    }

    #[test]
    fn http_proxy_scheme_stays_plaintext() {
        let cfg = config_from(&[("HTTPS_PROXY", "http://proxy.corp.com:8080")]).unwrap();
        let ep = cfg.proxy_for(UpstreamScheme::Https, "example.com").unwrap();
        assert!(ep.tls.is_none());
    }

    #[test]
    fn mixed_schemes_share_one_tls_config() {
        let cfg = config_from(&[
            ("HTTPS_PROXY", "https://proxy.corp.com:3130"),
            ("HTTP_PROXY", "https://proxy.corp.com:3130"),
        ])
        .unwrap();
        let https = cfg
            .proxy_for(UpstreamScheme::Https, "example.com")
            .unwrap()
            .tls
            .clone()
            .unwrap();
        let http = cfg
            .proxy_for(UpstreamScheme::Http, "example.com")
            .unwrap()
            .tls
            .clone()
            .unwrap();
        assert!(Arc::ptr_eq(&https, &http));
    }

    #[test]
    fn unreadable_proxy_ca_bundle_still_yields_config() {
        let cfg = config_from(&[
            ("HTTPS_PROXY", "https://proxy.corp.com"),
            (
                openshell_core::sandbox_env::PROXY_CA_BUNDLE,
                "/nonexistent/proxy-ca.pem",
            ),
        ])
        .unwrap();
        let ep = cfg.proxy_for(UpstreamScheme::Https, "example.com").unwrap();
        assert!(ep.tls.is_some(), "falls back to built-in and system roots");
    }

    #[test]
    fn proxy_ca_bundle_pem_reads_configured_file() {
        let ca_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(ca_file.path(), "PEM CONTENTS").unwrap();
        let path = ca_file.path().to_string_lossy().into_owned();
        let pem = proxy_ca_bundle_pem_with(&|name| {
            (name == openshell_core::sandbox_env::PROXY_CA_BUNDLE).then(|| path.clone())
        });
        assert_eq!(pem.as_deref(), Some("PEM CONTENTS"));
    }

    #[test]
    fn proxy_ca_bundle_pem_absent_or_unreadable_yields_none() {
        assert!(proxy_ca_bundle_pem_with(&|_| None).is_none());
        assert!(proxy_ca_bundle_pem_with(&|_| Some("  ".to_string())).is_none());
        assert!(proxy_ca_bundle_pem_with(&|_| Some("/nonexistent/ca.pem".to_string())).is_none());
    }

    #[test]
    fn userinfo_becomes_basic_auth() {
        let cfg = config_from(&[("HTTPS_PROXY", "http://user:p%40ss@proxy:8080")]).unwrap();
        let ep = cfg.proxy_for(UpstreamScheme::Https, "example.com").unwrap();
        let auth = ep.proxy_authorization.as_deref().unwrap();
        let expected = base64::engine::general_purpose::STANDARD.encode("user:p@ss");
        assert_eq!(auth, format!("Basic {expected}"));
    }

    #[test]
    fn debug_output_hides_credentials() {
        let cfg = config_from(&[("HTTPS_PROXY", "http://user:secret@proxy:8080")]).unwrap();
        let debug = format!("{cfg:?}");
        assert!(!debug.contains("secret"));
        assert!(!cfg.summary().contains("secret"));
    }

    #[test]
    fn ipv6_proxy_address_parses() {
        let cfg = config_from(&[("HTTPS_PROXY", "http://[fd00::1]:8080")]).unwrap();
        let ep = cfg.proxy_for(UpstreamScheme::Https, "example.com").unwrap();
        assert_eq!(ep.display_addr(), "fd00::1:8080");
    }

    // -- NO_PROXY matching --

    fn no_proxy_cfg(no_proxy: &str) -> UpstreamProxyConfig {
        config_from(&[("HTTPS_PROXY", "http://proxy:8080"), ("NO_PROXY", no_proxy)]).unwrap()
    }

    fn bypasses(cfg: &UpstreamProxyConfig, host: &str) -> bool {
        cfg.proxy_for(UpstreamScheme::Https, host).is_none()
    }

    #[test]
    fn no_proxy_domain_suffix_matches_host_and_subdomains() {
        let cfg = no_proxy_cfg("corp.com,other.example");
        assert!(bypasses(&cfg, "corp.com"));
        assert!(bypasses(&cfg, "api.corp.com"));
        assert!(!bypasses(&cfg, "notcorp.com"));
        assert!(!bypasses(&cfg, "corp.com.evil.io"));
    }

    #[test]
    fn no_proxy_leading_dot_and_wildcard_prefix_are_equivalent() {
        for entry in [".svc.cluster.local", "*.svc.cluster.local"] {
            let cfg = no_proxy_cfg(entry);
            assert!(
                bypasses(&cfg, "kubernetes.default.svc.cluster.local"),
                "{entry}"
            );
            assert!(!bypasses(&cfg, "example.com"), "{entry}");
        }
    }

    #[test]
    fn no_proxy_cidr_matches_ip_literals() {
        let cfg = no_proxy_cfg("10.96.0.0/12");
        assert!(bypasses(&cfg, "10.96.0.1"));
        assert!(bypasses(&cfg, "10.100.20.30"));
        assert!(!bypasses(&cfg, "10.200.0.9"));
        assert!(!bypasses(&cfg, "93.184.216.34"));
    }

    #[test]
    fn no_proxy_exact_ip_matches() {
        let cfg = no_proxy_cfg("192.168.1.5");
        assert!(bypasses(&cfg, "192.168.1.5"));
        assert!(!bypasses(&cfg, "192.168.1.6"));
    }

    #[test]
    fn no_proxy_wildcard_bypasses_everything() {
        let cfg = no_proxy_cfg("*");
        assert!(bypasses(&cfg, "example.com"));
    }

    #[test]
    fn no_proxy_ignores_port_qualifiers() {
        let cfg = no_proxy_cfg("internal.corp:8443");
        assert!(bypasses(&cfg, "internal.corp"));
        assert!(bypasses(&cfg, "svc.internal.corp"));
    }

    #[test]
    fn loopback_and_localhost_always_bypass() {
        let cfg = no_proxy_cfg("");
        assert!(bypasses(&cfg, "localhost"));
        assert!(bypasses(&cfg, "127.0.0.1"));
        assert!(bypasses(&cfg, "::1"));
        assert!(!bypasses(&cfg, "example.com"));
    }

    // -- CONNECT handshake --

    async fn fake_proxy(
        response: &'static str,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let mut used = 0;
            loop {
                let n = socket.read(&mut buf[used..]).await.unwrap();
                used += n;
                if n == 0 || buf[..used].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            socket.write_all(response.as_bytes()).await.unwrap();
            String::from_utf8_lossy(&buf[..used]).into_owned()
        });
        (addr, handle)
    }

    fn endpoint_for(addr: std::net::SocketAddr, auth: Option<&str>) -> ProxyEndpoint {
        ProxyEndpoint {
            host: addr.ip().to_string(),
            port: addr.port(),
            proxy_authorization: auth.map(str::to_string),
            tls: None,
        }
    }

    #[tokio::test]
    async fn connect_via_success_sends_connect_and_auth() {
        let (addr, handle) = fake_proxy("HTTP/1.1 200 Connection established\r\n\r\n").await;
        let endpoint = endpoint_for(addr, Some("Basic dXNlcjpwYXNz"));
        let stream = connect_via(&endpoint, "api.example.com", 443)
            .await
            .unwrap();
        drop(stream);
        let request = handle.await.unwrap();
        assert!(request.starts_with("CONNECT api.example.com:443 HTTP/1.1\r\n"));
        assert!(request.contains("Host: api.example.com:443\r\n"));
        assert!(request.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"));
    }

    #[tokio::test]
    async fn connect_via_rejects_non_200() {
        let (addr, _handle) =
            fake_proxy("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n").await;
        let endpoint = endpoint_for(addr, None);
        let err = connect_via(&endpoint, "api.example.com", 443)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("407"), "{err}");
    }

    #[tokio::test]
    async fn connect_via_rejects_malformed_response() {
        let (addr, _handle) = fake_proxy("garbage without status\r\n\r\n").await;
        let endpoint = endpoint_for(addr, None);
        let err = connect_via(&endpoint, "api.example.com", 443)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn connect_via_ipv6_target_is_bracketed() {
        let (addr, handle) = fake_proxy("HTTP/1.1 200 OK\r\n\r\n").await;
        let endpoint = endpoint_for(addr, None);
        let _ = connect_via(&endpoint, "2001:db8::1", 443).await.unwrap();
        let request = handle.await.unwrap();
        assert!(request.starts_with("CONNECT [2001:db8::1]:443 HTTP/1.1\r\n"));
    }

    // -- TLS (https://) proxies --

    /// A fake `https://` proxy: TLS server with a self-signed cert for
    /// 127.0.0.1 that answers CONNECT with 200. Returns the listen address,
    /// the server task (yielding the received CONNECT request), and the
    /// server certificate PEM to use as the corporate CA bundle.
    async fn fake_tls_proxy() -> (
        std::net::SocketAddr,
        tokio::task::JoinHandle<String>,
        String,
    ) {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let cert_pem = cert.pem();

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(socket).await.unwrap();
            let mut buf = vec![0u8; 4096];
            let mut used = 0;
            loop {
                let n = tls.read(&mut buf[used..]).await.unwrap();
                used += n;
                if n == 0 || buf[..used].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            tls.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
            tls.flush().await.unwrap();
            String::from_utf8_lossy(&buf[..used]).into_owned()
        });
        (addr, handle, cert_pem)
    }

    #[tokio::test]
    async fn connect_via_https_proxy_with_corporate_ca_bundle() {
        let (addr, handle, cert_pem) = fake_tls_proxy().await;
        let ca_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(ca_file.path(), cert_pem).unwrap();

        let proxy_url = format!("https://{addr}");
        let ca_path = ca_file.path().to_string_lossy().into_owned();
        let pairs = [
            ("HTTPS_PROXY", proxy_url.as_str()),
            (
                openshell_core::sandbox_env::PROXY_CA_BUNDLE,
                ca_path.as_str(),
            ),
        ];
        let cfg = config_from(&pairs).unwrap();
        let endpoint = cfg
            .proxy_for(UpstreamScheme::Https, "api.example.com")
            .unwrap();

        let stream = connect_via(endpoint, "api.example.com", 443).await.unwrap();
        assert!(matches!(stream, UpstreamStream::Tls(_)));
        drop(stream);
        let request = handle.await.unwrap();
        assert!(request.starts_with("CONNECT api.example.com:443 HTTP/1.1\r\n"));
    }

    #[tokio::test]
    async fn connect_via_https_proxy_rejects_untrusted_cert() {
        let (addr, _handle, _cert_pem) = fake_tls_proxy().await;

        // No corporate CA bundle: the self-signed proxy cert must not verify.
        let proxy_url = format!("https://{addr}");
        let pairs = [("HTTPS_PROXY", proxy_url.as_str())];
        let cfg = config_from(&pairs).unwrap();
        let endpoint = cfg
            .proxy_for(UpstreamScheme::Https, "api.example.com")
            .unwrap();

        let err = connect_via(endpoint, "api.example.com", 443)
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("TLS handshake with upstream proxy"),
            "{err}"
        );
    }
}
