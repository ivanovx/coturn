//! Telemetry: bounded event channel + lock-free atomic counters.
//! `emit` never blocks the caller (`try_send`).

use crate::types::AllocationId;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{info, warn};

pub mod http;

#[allow(dead_code)] // PolicyBlocked is used from Phase 3
#[derive(Debug, Clone)]
pub enum TelemetryEvent {
    AllocationOpened {
        allocation_id: AllocationId,
        client_addr: SocketAddr,
        relayed_addr: SocketAddr,
        username: String,
    },
    AllocationClosed {
        allocation_id: AllocationId,
        username: String,
        bytes_relayed: u64,
    },
    PolicyBlocked {
        client_addr: SocketAddr,
        target_ip: IpAddr,
        reason: &'static str,
    },
}

#[derive(Debug, Default)]
pub struct Metrics {
    pub active_allocations: AtomicUsize,
    pub total_relayed_bytes: AtomicU64,
    pub dropped_packets: AtomicU64,
    pub dropped_events: AtomicU64,
    pub allocations_total: AtomicU64,
    pub auth_failures: AtomicU64,
    pub policy_blocked: AtomicU64,
}

impl Metrics {
    /// Prometheus text exposition format (version 0.0.4).
    pub fn render_prometheus(&self) -> String {
        let mut out = String::new();
        let mut metric = |name: &str, kind: &str, help: &str, value: u64| {
            out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}\n"));
        };
        metric(
            "relay_active_allocations",
            "gauge",
            "Currently active TURN allocations.",
            self.active_allocations.load(Ordering::Relaxed) as u64,
        );
        metric(
            "relay_allocations_total",
            "counter",
            "Allocations created since start.",
            self.allocations_total.load(Ordering::Relaxed),
        );
        metric(
            "relay_relayed_bytes_total",
            "counter",
            "Payload bytes relayed in both directions.",
            self.total_relayed_bytes.load(Ordering::Relaxed),
        );
        metric(
            "relay_dropped_packets_total",
            "counter",
            "Packets dropped (no permission, full queue, send errors, oversize).",
            self.dropped_packets.load(Ordering::Relaxed),
        );
        metric(
            "relay_dropped_events_total",
            "counter",
            "Telemetry events dropped because the channel was full.",
            self.dropped_events.load(Ordering::Relaxed),
        );
        metric(
            "relay_auth_failures_total",
            "counter",
            "TURN requests rejected with 401/438.",
            self.auth_failures.load(Ordering::Relaxed),
        );
        metric(
            "relay_policy_blocked_total",
            "counter",
            "Peer addresses rejected by the IP policy (403).",
            self.policy_blocked.load(Ordering::Relaxed),
        );
        out
    }
}

#[derive(Clone)]
pub struct Telemetry {
    tx: mpsc::Sender<TelemetryEvent>,
    metrics: Arc<Metrics>,
}

impl Telemetry {
    /// Spawns the consumer. It exits (after logging a summary) once every
    /// `Telemetry` clone has been dropped.
    pub fn spawn(capacity: usize) -> (Self, JoinHandle<()>) {
        let (tx, mut rx) = mpsc::channel::<TelemetryEvent>(capacity);
        let metrics = Arc::new(Metrics::default());
        let m = metrics.clone();
        let task = tokio::spawn(async move {
            while let Some(ev) = rx.recv().await {
                match ev {
                    TelemetryEvent::AllocationOpened { allocation_id, client_addr, relayed_addr, username } => {
                        info!(id = allocation_id.0, %client_addr, %relayed_addr, %username, "allocation opened");
                    }
                    TelemetryEvent::AllocationClosed { allocation_id, username, bytes_relayed } => {
                        info!(id = allocation_id.0, %username, bytes_relayed, "allocation closed");
                    }
                    TelemetryEvent::PolicyBlocked { client_addr, target_ip, reason } => {
                        warn!(%client_addr, %target_ip, reason, "policy blocked");
                    }
                }
            }
            info!(
                active = m.active_allocations.load(Ordering::Relaxed),
                relayed_bytes = m.total_relayed_bytes.load(Ordering::Relaxed),
                dropped_packets = m.dropped_packets.load(Ordering::Relaxed),
                dropped_events = m.dropped_events.load(Ordering::Relaxed),
                "telemetry flushed"
            );
        });
        (Telemetry { tx, metrics }, task)
    }

    pub fn emit(&self, ev: TelemetryEvent) {
        if self.tx.try_send(ev).is_err() {
            self.metrics.dropped_events.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn metrics(&self) -> Arc<Metrics> {
        self.metrics.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prometheus_output_contains_all_metrics() {
        let m = Metrics::default();
        m.active_allocations.store(3, Ordering::Relaxed);
        m.total_relayed_bytes.store(1234, Ordering::Relaxed);
        let text = m.render_prometheus();
        assert!(text.contains("# TYPE relay_active_allocations gauge\nrelay_active_allocations 3\n"));
        assert!(text.contains("relay_relayed_bytes_total 1234\n"));
        for name in [
            "relay_allocations_total",
            "relay_dropped_packets_total",
            "relay_dropped_events_total",
            "relay_auth_failures_total",
            "relay_policy_blocked_total",
        ] {
            assert!(text.contains(name), "missing {name}");
        }
    }
}
