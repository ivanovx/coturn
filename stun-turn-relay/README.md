# stun-turn-relay

Lightweight STUN/TURN relay (UDP) for an E2EE messenger. Rust + tokio, no coturn legacy.
Implements STUN Binding, TURN Allocate / Refresh / CreatePermission / ChannelBind,
Send/Data indications and ChannelData, with time-limited HMAC credentials.

> Status: written to the architecture spec, phases 1-4 implemented. It has **not been compiled or
> run by its author's tooling yet** - run `cargo test` first and fix anything the compiler reports.

## Documentation

Full documentation with Mermaid diagrams (architecture, class and behavior diagrams, protocol and
security, operations, coturn migration) is in [docs/](docs/README.md).

## Quick start

```bash
cargo test                      # unit + end-to-end tests over loopback
cp .env.example .env            # set EXTERNAL_IP, AUTH_SECRET, REALM
docker compose up --build -d
```

## Configuration (environment)

| Variable | Default | Description |
|---|---|---|
| `AUTH_SECRET` | **required** (>= 16 chars) | Shared secret with the messenger backend |
| `LISTEN_ADDR` | `0.0.0.0:3478` | STUN/TURN entry socket |
| `EXTERNAL_IP` | listen IP | Public IP advertised in `XOR-RELAYED-ADDRESS` |
| `REALM` | `relay` | TURN realm in 401/438 challenges |
| `AUTH_HMAC_ALGO` | `sha256` | Password hash: `sha1` (coturn `use-auth-secret`), `sha256`, or `sha1,sha256` (migration) |
| `CREDENTIAL_GRACE_SECS` | `3600` | Expired credentials still work for an *existing* allocation this long (0 = off, max 86400) |
| `ALLOWED_PEER_IPS` | empty | Peer exceptions overriding all deny rules (IP, CIDR or `a-b` range, comma separated) |
| `DENIED_PEER_IPS` | empty | Extra denied peer ranges |
| `RELAY_MIN_PORT` / `RELAY_MAX_PORT` | `49152` / `49352` | Relay port range, **one port per allocation** (range size = max concurrent allocations); publish the same range in Docker |
| `MAX_ALLOCATIONS` | `2000` | Global allocation limit (-> 508) |
| `MAX_ALLOCATIONS_PER_USER` | `16` | Per `user_id` limit (-> 486) |
| `ALLOCATION_LIFETIME_SECS` | `300` | Default lifetime, hard cap 600 |
| `CHANNEL_CAP` | `512` | Bounded queue per allocation |
| `METRICS_ADDR` | unset | e.g. `127.0.0.1:9100` enables `/metrics` + `/healthz` |
| `ALLOW_PRIVATE_PEERS` | `false` | **Dev only**: allow loopback/private peers |
| `RUST_LOG` | `info` | tracing filter |

## Credentials (integration with the messenger backend)

```
username = "<expiry_unix>:<user_id>"            (a bare "<expiry_unix>" also works, like in coturn)
password = base64(HMAC-<algo>(AUTH_SECRET, username))   algo = SHA-1 (coturn-compatible) or SHA-256
```

With `AUTH_HMAC_ALGO=sha1` and the same secret/realm the credentials generated for coturn's
`use-auth-secret` are accepted unchanged. See [docs/06-coturn-migration.md](docs/06-coturn-migration.md).

Hand `username`, `password` and the realm to the client for the call. Clients then use the standard
TURN long-term mechanism (USERNAME / REALM / NONCE / MESSAGE-INTEGRITY), so stock WebRTC stacks work.
The server derives the password statelessly. Nonces are stateless too and valid for 10 minutes.
Per-user quotas are keyed by `user_id`, so renewing credentials does not reset them.

For manual testing:

```bash
AUTH_SECRET=... REALM=relay.example.org stun-turn-relay mint-credentials alice 3600
# or: docker compose run --rm relay mint-credentials alice 3600
```

## Long calls

Credentials are checked on every request, but requests on an **existing** allocation (Refresh,
CreatePermission, ChannelBind) are checked against the allocation's owner and accept credentials
that expired up to `CREDENTIAL_GRACE_SECS` ago. Expired credentials can never create a new allocation.
Maximum call length without re-issuing credentials = credential TTL + grace.

## Security model

- Every TURN request needs valid credentials (401/438 with a fresh challenge otherwise); success
  responses carry MESSAGE-INTEGRITY.
- Refresh/CreatePermission/ChannelBind must come from the allocation's owner (same `user_id`).
- Peers in loopback, private, link-local, unspecified, multicast and broadcast ranges (incl. IPv6
  ULA and IPv4-mapped) are refused with 403 for CreatePermission and ChannelBind. A permission can
  only exist for an allowed peer, so Send/ChannelData cannot reach a blocked address either.
- Datagrams are capped at 2048 bytes, all queues are bounded, control requests are rate-bounded
  (1024 in flight), permissions (256) and channels (128) are capped per allocation.
- The container runs as non-root, read-only, with all capabilities dropped.
- The relay only forwards opaque SRTP; it never sees media keys.
- The metrics endpoint has no authentication: bind it to loopback or an internal network.

## Observability

`METRICS_ADDR=127.0.0.1:9100` exposes Prometheus metrics: `relay_active_allocations`,
`relay_allocations_total`, `relay_relayed_bytes_total`, `relay_dropped_packets_total`,
`relay_auth_failures_total`, `relay_policy_blocked_total`, `relay_dropped_events_total`.
On SIGTERM the server stops reading, closes all allocations, and logs a telemetry summary.

## Load testing

```bash
# server under test: ALLOW_PRIVATE_PEERS=true if the echo peer is on loopback/private IPs
AUTH_SECRET=... REALM=relay stun-turn-relay loadtest 203.0.113.10:3478 200 30 50 160
#                                                     server           clients secs pps payload
```

Each simulated client does Allocate -> ChannelBind -> ChannelData; an in-process peer echoes the
packets. The report shows RTT percentiles, jitter and loss. For realistic numbers run it from a
different machine, set `LOADTEST_PEER_IP` to an address the relay can reach, and watch
`docker stats` for the relay's memory. Simulating real NATs and ICE is out of scope for this tool.

## Design notes / deviations from the spec

- Peer -> client packets are sent by the `AllocationActor` directly through the shared main socket
  instead of via `RegistryEvent::RelayedFromPeer` (one hop less on the media path).
- `RegistryCmd::LookupByClient` is replaced by the shared `DashMap` lookup (spec section 2.2).
- Shared types live in `src/types.rs`; `auth/policy.rs` holds the IP policy.
- Not implemented: TURN-over-TCP, TLS/DTLS (UDP only), external user backends. See the coturn migration notes.
