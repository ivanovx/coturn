//! Minimal HTTP/1.1 endpoint for metrics (no extra dependencies):
//!   GET /metrics  -> Prometheus text format
//!   GET /healthz  -> "ok"
//! No authentication: bind it to loopback or an internal network only.

use super::Metrics;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tokio::time::{sleep, timeout};
use tracing::{debug, warn};

const MAX_CONNECTIONS: usize = 64;

pub async fn serve(listener: TcpListener, metrics: Arc<Metrics>, mut shutdown: watch::Receiver<bool>) {
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            res = listener.accept() => match res {
                Ok((stream, peer)) => {
                    let Ok(permit) = slots.clone().try_acquire_owned() else {
                        debug!(%peer, "metrics: too many connections");
                        continue;
                    };
                    let m = metrics.clone();
                    tokio::spawn(async move {
                        handle(stream, m).await;
                        drop(permit);
                    });
                }
                Err(e) => {
                    warn!(error = %e, "metrics accept failed");
                    sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
}

async fn handle(mut stream: TcpStream, metrics: Arc<Metrics>) {
    let mut buf = [0u8; 1024];
    let n = match timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => return,
    };
    let request = String::from_utf8_lossy(&buf[..n]);
    let first_line = request.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();

    let (status, content_type, body) = match parts.as_slice() {
        ["GET", path, ..] if path.split('?').next() == Some("/metrics") => {
            ("200 OK", "text/plain; version=0.0.4; charset=utf-8", metrics.render_prometheus())
        }
        ["GET", "/healthz", ..] => ("200 OK", "text/plain; charset=utf-8", "ok\n".to_string()),
        ["GET", ..] => ("404 Not Found", "text/plain; charset=utf-8", "not found\n".to_string()),
        _ => (
            "405 Method Not Allowed",
            "text/plain; charset=utf-8",
            "method not allowed\n".to_string(),
        ),
    };

    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    async fn get(addr: std::net::SocketAddr, request: &str) -> String {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(request.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        timeout(Duration::from_secs(2), s.read_to_end(&mut out)).await.unwrap().unwrap();
        String::from_utf8(out).unwrap()
    }

    #[tokio::test]
    async fn serves_metrics_health_and_404() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let metrics = Arc::new(Metrics::default());
        metrics.active_allocations.store(7, Ordering::Relaxed);
        let (tx, rx) = watch::channel(false);
        tokio::spawn(serve(listener, metrics, rx));

        let r = get(addr, "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(r.starts_with("HTTP/1.1 200 OK"));
        assert!(r.contains("relay_active_allocations 7"));

        let r = get(addr, "GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(r.starts_with("HTTP/1.1 200 OK") && r.ends_with("ok\n"));

        let r = get(addr, "GET /nope HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(r.starts_with("HTTP/1.1 404"));

        let r = get(addr, "POST /metrics HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(r.starts_with("HTTP/1.1 405"));

        tx.send(true).unwrap();
    }
}
