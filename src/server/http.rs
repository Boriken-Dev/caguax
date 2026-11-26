//! The HTTP proxy listener: `CONNECT`, forwarded requests and the PAC file.

use alloc::string::String;
use alloc::sync::Arc;
use core::net::SocketAddr;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt as _, Empty, Full};
use hyper::body::Incoming;
use hyper::header::{
    CONNECTION, CONTENT_TYPE, HOST, HeaderMap, HeaderName, HeaderValue, PROXY_AUTHENTICATE,
    PROXY_AUTHORIZATION, TRANSFER_ENCODING, UPGRADE,
};
use hyper::{Method, Request, Response, StatusCode, Uri, Version};
use hyper_util::rt::TokioIo;

use super::{Inner, OpenOptions, RelayOptions, relay};
use crate::connection::{Connection, LISTENER, Scheme, bracket, join_host};
use crate::error::Error;
use crate::record::RecordedStream;
use crate::route::{Action, Route, TlsSource};
use crate::server::IdleRead;

pub(super) type Body = BoxBody<Bytes, hyper::Error>;

/// One accepted client connection of the HTTP proxy listener.
#[derive(Clone)]
pub(super) struct ClientConnection {
    pub(super) inner: Arc<Inner>,
    pub(super) peer: SocketAddr,
    pub(super) local: Option<SocketAddr>,
    /// Held by every task that outlives the request (a tunnel), so `max_connections` counts it.
    pub(super) admission: Arc<super::Admission>,
}

/// Hop-by-hop headers (RFC 9110 section 7.6.1) plus the proxy-only ones; the names a `Connection`
/// header lists are dropped as well.
const HOP_BY_HOP: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authorization",
    "proxy-authenticate",
    "te",
    "trailer",
    "upgrade",
];

fn respond(status: StatusCode, content_type: &str, text: impl Into<Bytes>) -> Response<Body> {
    let mut response = Response::new(
        Full::new(text.into())
            .map_err(|never| match never {})
            .boxed(),
    );
    *response.status_mut() = status;
    if let Ok(value) = HeaderValue::from_str(content_type) {
        response.headers_mut().insert(CONTENT_TYPE, value);
    }
    response
}

fn text(status: StatusCode, message: impl Into<String>) -> Response<Body> {
    respond(status, "text/plain; charset=utf-8", message.into())
}

fn fail(error: &Error, target: &str) -> Response<Body> {
    match error {
        Error::Timeout(_) => text(
            StatusCode::GATEWAY_TIMEOUT,
            alloc::format!("timed out reaching {target}\n"),
        ),
        other => text(StatusCode::BAD_GATEWAY, alloc::format!("{other}\n")),
    }
}

fn describe(route: &Route) -> String {
    if route.name().is_empty() {
        route.action().as_str().into()
    } else {
        alloc::format!("{} ({})", route.action(), route.name())
    }
}

fn listed(headers: &HeaderMap) -> alloc::vec::Vec<String> {
    headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| !token.is_empty())
        .collect()
}

/// The headers that go on to the other side.
fn end_to_end(headers: &HeaderMap) -> HeaderMap {
    let named = listed(headers);
    let mut kept = HeaderMap::new();
    for (name, value) in headers {
        let lower = name.as_str();
        if HOP_BY_HOP.contains(&lower) || named.iter().any(|token| token == lower) {
            continue;
        }
        kept.append(name.clone(), value.clone());
    }
    kept
}

fn wants_upgrade(headers: &HeaderMap) -> Option<HeaderValue> {
    let upgrade = headers.get(UPGRADE)?;
    listed(headers)
        .iter()
        .any(|token| token == "upgrade")
        .then(|| upgrade.clone())
}

/// The octets of the request head: the request line and every header line.
fn head_size(request: &Request<Incoming>) -> usize {
    let line =
        request.method().as_str().len() + request.uri().to_string().len() + " HTTP/1.1\r\n".len();
    request.headers().iter().fold(line, |sum, (name, value)| {
        sum + name.as_str().len() + value.len() + 4
    })
}

/// `407`, closing the connection: the client must present the listener's login.
fn login_required() -> Response<Body> {
    let mut response = text(
        StatusCode::PROXY_AUTHENTICATION_REQUIRED,
        "this proxy needs a login (Proxy-Authorization: Basic)\n",
    );
    let headers = response.headers_mut();
    headers.insert(
        PROXY_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"caguax\""),
    );
    headers.insert(CONNECTION, HeaderValue::from_static("close"));
    response
}

pub(super) async fn handle(client: ClientConnection, request: Request<Incoming>) -> Response<Body> {
    let state = client.inner.state();
    if head_size(&request) > state.settings.max_head_bytes {
        return text(StatusCode::BAD_REQUEST, "request head too large\n");
    }
    if let Some(login) = &state.login
        && !login.accepts_any(
            request
                .headers()
                .get_all(PROXY_AUTHORIZATION)
                .iter()
                .map(HeaderValue::as_bytes),
        )
    {
        tracing::info!(target: "caguax", peer = %client.peer, "refused: no valid proxy login");
        return login_required();
    }
    drop(state);
    if request.method() == Method::CONNECT {
        return connect_request(client, request).await;
    }
    if request.uri().scheme().is_some() && request.uri().authority().is_some() {
        return forward_request(client, request).await;
    }
    if request.uri().path().starts_with('/') {
        return local(&client, &request);
    }
    text(StatusCode::BAD_REQUEST, "malformed request line\n")
}

fn local(client: &ClientConnection, request: &Request<Incoming>) -> Response<Body> {
    let wanted = matches!(*request.method(), Method::GET | Method::HEAD)
        && request.uri().path() == "/proxy.pac";
    if !wanted {
        return text(StatusCode::NOT_FOUND, "only /proxy.pac is served here\n");
    }
    let state = client.inner.state();
    let Some(router) = state.router.router() else {
        return text(StatusCode::NOT_FOUND, "only /proxy.pac is served here\n");
    };
    let proxy = client.local.map_or_else(String::new, |local| {
        join_host(&local.ip().to_string(), local.port())
    });
    let script = router.pac_script(&proxy, state.settings.egress.as_ref());
    let body = if *request.method() == Method::GET {
        Bytes::from(script)
    } else {
        Bytes::new()
    };
    respond(StatusCode::OK, "application/x-ns-proxy-autoconfig", body)
}

fn connection_for(
    host: &str,
    port: u16,
    scheme: Scheme,
    path: Option<String>,
    peer: SocketAddr,
) -> Option<Connection> {
    let mut builder = Connection::builder(host, port)
        .scheme(scheme)
        .client(peer)
        .listener(LISTENER);
    if let Some(path) = path {
        builder = builder.path(path);
    }
    builder.build().ok()
}

/// Whether the authority names a port that is not a number from 0 to 65535.
fn bad_port(authority: &hyper::http::uri::Authority) -> bool {
    let text = authority.as_str();
    let host_port = text.rsplit_once('@').map_or(text, |(_, rest)| rest);
    if host_port.ends_with(']') {
        return false;
    }
    host_port
        .rsplit_once(':')
        .is_some_and(|(_, port)| port.parse::<u16>().is_err())
}

fn empty() -> Body {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

async fn connect_request(
    client: ClientConnection,
    mut request: Request<Incoming>,
) -> Response<Body> {
    let state = client.inner.state();
    let Some(authority) = request.uri().authority().cloned() else {
        return text(StatusCode::BAD_REQUEST, "malformed CONNECT target\n");
    };
    if bad_port(&authority) {
        return text(StatusCode::BAD_REQUEST, "malformed CONNECT target\n");
    }
    let Some(connection) = connection_for(
        authority.host(),
        authority.port_u16().unwrap_or(443),
        Scheme::Https,
        None,
        client.peer,
    ) else {
        return text(StatusCode::BAD_REQUEST, "malformed CONNECT target\n");
    };
    let route = state.router.route(&connection);
    tracing::info!(
        target: "caguax",
        "CONNECT {} -> {}",
        connection.authority(),
        describe(&route)
    );
    let intercept = match route.action() {
        Action::Reject => {
            return text(
                StatusCode::FORBIDDEN,
                alloc::format!("{} is not allowed\n", connection.authority()),
            );
        }
        Action::Tls => match &state.interceptor {
            Some(interceptor) => Some(Arc::clone(interceptor)),
            None => {
                return text(
                    StatusCode::BAD_GATEWAY,
                    "this destination needs TLS interception, and the proxy has no CA\n",
                );
            }
        },
        Action::Direct => None,
    };
    let upstream = match client
        .inner
        .open_upstream(&connection, &route, OpenOptions::default())
        .await
    {
        Ok(upstream) => upstream,
        Err(error) => return fail(&error, &connection.authority()),
    };
    let recording = client
        .inner
        .start_recording(&connection, &route, Some(client.peer), &upstream);
    let on_upgrade = hyper::upgrade::on(&mut request);
    let inner = Arc::clone(&client.inner);
    let host = connection.host().to_owned();
    let admission = Arc::clone(&client.admission);
    inner.clone().spawn(async move {
        let _admission = admission;
        let Ok(upgraded) = on_upgrade.await else {
            if let Some(recording) = &recording {
                recording.closed();
            }
            return;
        };
        let stream = TokioIo::new(upgraded);
        match intercept {
            Some(interceptor) => {
                let timeout = inner.state().settings.connect_timeout;
                match interceptor.accept(&host, stream, timeout).await {
                    Ok(tls) => {
                        inner
                            .relay_session(tls, upstream, recording, None, true)
                            .await;
                    }
                    Err(error) => {
                        tracing::info!(
                            target: "caguax",
                            "client TLS for {host} failed: {error}"
                        );
                        if let Some(recording) = &recording {
                            recording.closed();
                        }
                    }
                }
            }
            None => {
                inner
                    .relay_session(stream, upstream, recording, None, false)
                    .await;
            }
        }
    });
    let mut response = Response::new(empty());
    response
        .extensions_mut()
        .insert(hyper::ext::ReasonPhrase::from_static(
            b"Connection established",
        ));
    response
}

async fn plain_tls(inner: &Inner) -> Result<Arc<rustls::ClientConfig>, Error> {
    inner
        .plain_tls
        .get_or_try_init(|| async {
            let tls = coqui_sslcontext::Tls::builder()
                .client_certificates(coqui_sslcontext::ClientCertificates::None)
                .build()?;
            Ok::<_, Error>(tls.client_config("")?)
        })
        .await
        .cloned()
}

async fn forward_request(
    client: ClientConnection,
    mut request: Request<Incoming>,
) -> Response<Body> {
    let state = client.inner.state();
    let uri = request.uri().clone();
    let scheme = match uri.scheme_str() {
        Some(scheme) if scheme.eq_ignore_ascii_case("http") => Scheme::Http,
        Some(scheme) if scheme.eq_ignore_ascii_case("https") => Scheme::Https,
        _ => {
            return text(
                StatusCode::BAD_REQUEST,
                "expected an absolute http(s) URL\n",
            );
        }
    };
    let Some(host) = uri.host() else {
        return text(
            StatusCode::BAD_REQUEST,
            "expected an absolute http(s) URL\n",
        );
    };
    if uri.authority().is_some_and(bad_port) {
        return text(
            StatusCode::BAD_REQUEST,
            "expected an absolute http(s) URL\n",
        );
    }
    let port = uri
        .port_u16()
        .unwrap_or(if scheme == Scheme::Https { 443 } else { 80 });
    let path = uri
        .path_and_query()
        .map_or_else(|| "/".to_owned(), |path| path.as_str().to_owned());
    let path = if path.is_empty() {
        "/".to_owned()
    } else {
        path
    };
    let Some(connection) = connection_for(host, port, scheme, Some(path.clone()), client.peer)
    else {
        return text(
            StatusCode::BAD_REQUEST,
            "expected an absolute http(s) URL\n",
        );
    };
    let mut route = state.router.route(&connection);
    tracing::info!(
        target: "caguax",
        "{} {} -> {}",
        request.method(),
        alloc::format!("{}://{}{}", scheme.as_str(), connection.authority(), uri.path()),
        describe(&route)
    );
    if route.action() == Action::Reject {
        return text(
            StatusCode::FORBIDDEN,
            alloc::format!("{} is not allowed\n", connection.authority()),
        );
    }
    if scheme == Scheme::Https && route.action() == Action::Direct {
        let tls = match plain_tls(&client.inner).await {
            Ok(tls) => tls,
            Err(error) => return fail(&error, &connection.authority()),
        };
        let mut builder = Route::with_tls(TlsSource::Config(tls)).name(route.name());
        if let Some(upstream) = route.upstream() {
            builder = builder.upstream(upstream.clone());
        }
        route = builder.build();
    }
    let upstream = match client
        .inner
        .open_upstream(&connection, &route, OpenOptions { forward_http: true })
        .await
    {
        Ok(upstream) => upstream,
        Err(error) => return fail(&error, &connection.authority()),
    };
    let default_port = if upstream.tls() { 443 } else { 80 };
    let authority = if connection.port() == default_port {
        bracket(connection.host())
    } else {
        connection.authority()
    };
    let forward = upstream.forward();
    let proxy_authorization = upstream.proxy_authorization().map(str::to_owned);
    let upstream_tls = upstream.tls();
    let target: Uri = if forward {
        match alloc::format!("http://{authority}{path}").parse() {
            Ok(target) => target,
            Err(_) => return text(StatusCode::BAD_REQUEST, "malformed request target\n"),
        }
    } else {
        match path.parse() {
            Ok(target) => target,
            Err(_) => return text(StatusCode::BAD_REQUEST, "malformed request target\n"),
        }
    };
    let upgrade = wants_upgrade(request.headers());
    let client_upgrade = upgrade.as_ref().map(|_| hyper::upgrade::on(&mut request));
    let (parts, body) = request.into_parts();
    let mut headers = end_to_end(&parts.headers);
    headers.remove(HOST);
    headers.remove(TRANSFER_ENCODING);
    let mut outgoing = Request::new(body);
    *outgoing.method_mut() = parts.method;
    *outgoing.uri_mut() = target;
    *outgoing.version_mut() = Version::HTTP_11;
    *outgoing.headers_mut() = headers;
    if let Ok(value) = HeaderValue::from_str(&authority) {
        outgoing.headers_mut().insert(HOST, value);
    }
    match &upgrade {
        Some(upgrade) => {
            outgoing
                .headers_mut()
                .insert(CONNECTION, HeaderValue::from_static("Upgrade"));
            outgoing.headers_mut().insert(UPGRADE, upgrade.clone());
        }
        None => {
            outgoing
                .headers_mut()
                .insert(CONNECTION, HeaderValue::from_static("close"));
        }
    }
    if forward
        && let Some(authorization) = proxy_authorization
        && let Ok(mut value) = HeaderValue::from_str(&authorization)
    {
        value.set_sensitive(true);
        outgoing.headers_mut().insert(PROXY_AUTHORIZATION, value);
    }
    let recording = client
        .inner
        .start_recording(&connection, &route, Some(client.peer), &upstream);
    let idle = state.settings.idle_timeout;
    let io = TokioIo::new(RecordedStream::new(
        IdleRead::new(upstream, idle),
        recording,
    ));
    let (mut sender, upstream_connection) = match hyper::client::conn::http1::handshake(io).await {
        Ok(pair) => pair,
        Err(error) => {
            return text(StatusCode::BAD_GATEWAY, alloc::format!("{error}\n"));
        }
    };
    client.inner.spawn(async move {
        let _ = upstream_connection.with_upgrades().await;
    });
    let sent = tokio::time::timeout(
        state.settings.connect_timeout,
        sender.send_request(outgoing),
    )
    .await;
    let mut response = match sent {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            return text(
                StatusCode::BAD_GATEWAY,
                alloc::format!("{} did not answer: {error}\n", connection.authority()),
            );
        }
        Err(_) => {
            return text(
                StatusCode::GATEWAY_TIMEOUT,
                alloc::format!("timed out reaching {}\n", connection.authority()),
            );
        }
    };
    if response.status() == StatusCode::SWITCHING_PROTOCOLS
        && let Some(client_upgrade) = client_upgrade
    {
        let upstream_upgrade = hyper::upgrade::on(&mut response);
        let (parts, _) = response.into_parts();
        let mut switched = Response::new(empty());
        *switched.status_mut() = parts.status;
        *switched.headers_mut() = parts.headers;
        let options = RelayOptions {
            idle_timeout: state.settings.idle_timeout,
            buffer: state.settings.relay_buffer,
            close_timeout: state.settings.close_timeout,
            end_both: upstream_tls,
        };
        let admission = Arc::clone(&client.admission);
        client.inner.spawn(async move {
            let _admission = admission;
            if let (Ok(client_side), Ok(upstream_side)) =
                (client_upgrade.await, upstream_upgrade.await)
            {
                relay(
                    TokioIo::new(client_side),
                    TokioIo::new(upstream_side),
                    options,
                )
                .await;
            }
        });
        return switched;
    }
    let (mut parts, body) = response.into_parts();
    let named = listed(&parts.headers);
    let drop_names: alloc::vec::Vec<HeaderName> = parts
        .headers
        .keys()
        .filter(|name| {
            let lower = name.as_str();
            HOP_BY_HOP.contains(&lower)
                || lower == "transfer-encoding"
                || named.iter().any(|token| token == lower)
        })
        .cloned()
        .collect();
    for name in drop_names {
        parts.headers.remove(name);
    }
    Response::from_parts(parts, body.boxed())
}
