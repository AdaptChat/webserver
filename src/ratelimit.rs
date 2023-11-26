use crate::response::Response;

use axum::{
    body::Body,
    extract::ConnectInfo,
    headers::HeaderMap,
    http::{header::FORWARDED, Request},
    response::{IntoResponse, Response as AxumResponse},
};
use dashmap::DashMap;
use essence::Error;
use forwarded_header_value::{ForwardedHeaderValue, Identifier};
use tower::{Layer, Service};

use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;

#[derive(Clone, Debug, Hash)]
pub struct Bucket {
    pub count: u16,
    pub reset: Instant,
    pub previous: Option<Instant>,
}

impl Bucket {
    #[must_use]
    pub const fn new(count: u16, reset: Instant) -> Self {
        Self {
            count,
            reset,
            previous: None,
        }
    }
}

#[derive(Debug)]
pub struct Ratelimit<S> {
    inner: S,
    rate: u16,
    per: u16,
    buckets: Arc<DashMap<IpAddr, Bucket>>,
}

impl<S> Ratelimit<S> {
    #[inline]
    fn insert_headers(rate: u16, per: u16, headers: &mut HeaderMap) {
        headers.insert("X-RateLimit-Limit", rate.to_string().parse().unwrap());
        headers.insert("X-RateLimit-Per", per.to_string().parse().unwrap());
    }

    #[allow(clippy::cast_lossless)]
    fn handle_ratelimit(&self, ip: IpAddr) -> Result<u16, AxumResponse> {
        let mut bucket = self
            .buckets
            .entry(ip)
            .or_insert_with(|| Bucket::new(self.rate, Instant::now()));

        if bucket.reset > Instant::now() {
            let retry_after = bucket.reset.duration_since(Instant::now());

            let mut response = Response::from(Error::Ratelimited {
                retry_after: retry_after.as_secs_f32(),
                ip: ip.to_string(),
                message: format!("You are being rate limited. Try again in {retry_after:?}.",),
            })
            .into_response();

            let headers = response.headers_mut();
            Self::insert_headers(self.rate, self.per, headers);
            headers.insert("X-RateLimit-Remaining", "0".parse().unwrap());
            headers.insert(
                "Retry-After",
                retry_after.as_secs_f32().to_string().parse().unwrap(),
            );

            return Err(response);
        }

        let elapsed = bucket
            .previous
            .map_or(Duration::from_secs(0), |previous| previous.elapsed());

        // Replenish missed tokens into the bucket
        let unit = self.per as f32 / self.rate as f32;
        let count = (elapsed.as_secs_f32() / unit).floor() as u16;
        bucket.count = (bucket.count + count).min(self.rate) - 1;

        if bucket.count == 0 {
            bucket.count = self.rate;
            bucket.reset =
                bucket.previous.unwrap_or_else(Instant::now) + Duration::from_secs(self.per as u64);
        }

        bucket.previous = Some(Instant::now());
        Ok(bucket.count)
    }
}

impl<S> Service<Request<Body>> for Ratelimit<S>
where
    S: Clone + Service<Request<Body>, Response = AxumResponse> + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let Some(ip) = get_ip(&req) else {
            return Box::pin(async {
                Ok(Response::from(Error::MalformedIp {
                    message: String::from(
                        "Could not resolve an IP address from the request. \
                        We require a valid IP address to protect us from DoS attacks.",
                    ),
                })
                .into_response())
            });
        };

        match self.handle_ratelimit(ip) {
            Ok(count) => {
                let clone = self.inner.clone();
                let mut inner = std::mem::replace(&mut self.inner, clone);
                let (rate, per) = (self.rate, self.per);

                Box::pin(async move {
                    let mut result = inner.call(req).await?;
                    let headers = result.headers_mut();

                    Self::insert_headers(rate, per, headers);
                    headers.insert("X-RateLimit-Remaining", count.to_string().parse().unwrap());

                    Ok(result)
                })
            }
            Err(res) => Box::pin(async { Ok(res) }),
        }
    }
}

#[derive(Clone, Debug)]
pub struct RatelimitLayer {
    pub rate: u16,
    pub per: u16,
    pub buckets: Arc<DashMap<IpAddr, Bucket>>,
}

impl RatelimitLayer {
    #[must_use]
    pub fn new(rate: u16, per: u16) -> Self {
        Self {
            rate,
            per,
            buckets: Arc::new(DashMap::new()),
        }
    }
}

impl<S> Layer<S> for RatelimitLayer {
    type Service = Ratelimit<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Ratelimit {
            inner,
            rate: self.rate,
            per: self.per,
            buckets: self.buckets.clone(),
        }
    }
}

// Implmentation from https://github.com/imbolc/axum-client-ip/blob/main/src/lib.rs
fn get_ip(req: &Request<Body>) -> Option<IpAddr> {
    let headers = req.headers();

    headers
        .get("x-forwarded-for")
        .and_then(|hv| hv.to_str().ok())
        .and_then(|s| s.split(',').find_map(|s| s.trim().parse::<IpAddr>().ok()))
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|hv| hv.to_str().ok())
                .and_then(|s| s.parse::<IpAddr>().ok())
        })
        .or_else(|| {
            headers.get_all(FORWARDED).iter().find_map(|hv| {
                hv.to_str()
                    .ok()
                    .and_then(|s| ForwardedHeaderValue::from_forwarded(s).ok())
                    .and_then(|f| {
                        f.iter()
                            .filter_map(|fs| fs.forwarded_for.as_ref())
                            .find_map(|ident| match ident {
                                Identifier::SocketAddr(a) => Some(a.ip()),
                                Identifier::IpAddr(ip) => Some(*ip),
                                _ => None,
                            })
                    })
            })
        })
        .or_else(|| {
            req.extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ConnectInfo(addr)| addr.ip())
        })
}

macro_rules! ratelimit {
    ($rate:expr, $per:expr) => {{
        tower::ServiceBuilder::new()
            .layer(axum::error_handling::HandleErrorLayer::new(|_| async { unreachable!() }))
            .layer(tower::buffer::BufferLayer::new(1024))
            .layer(crate::ratelimit::RatelimitLayer::new($rate, $per))
    }};
}

pub(crate) use ratelimit;
