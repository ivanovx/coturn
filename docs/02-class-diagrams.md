# 2. Клас диаграми

Диаграмите показват структурата на кода. За четимост типовете са опростени (без lifetimes и generic параметри); точните сигнатури са в сорс кода. Името на модула е в заглавието на всяка секция.

Условности: `+` публично, `-` частно, `<<enumeration>>` е Rust `enum`, `<<module>>` е група свободни функции.

## 2.1 Протоколен слой (`protocol::stun`, `protocol::turn`)

```mermaid
classDiagram
    direction LR
    class StunMessage {
        +MessageClass class
        +u16 method
        +bytes12 transaction_id
        +List attributes
        +parse(data) Result
        +encode(with_fingerprint) Bytes
        +encode_with_integrity(key, with_fingerprint) Bytes
        +attribute(kind) Option
        +binding_success(txn, mapped) StunMessage
    }
    class Attribute {
        +u16 kind
        +Bytes value
    }
    class MessageClass {
        <<enumeration>>
        Request
        Indication
        SuccessResponse
        ErrorResponse
    }
    class StunModule {
        <<module>>
        +looks_like_stun(buf) bool
        +integrity_parts(raw) Option
        +encode_xor_address(addr, txn) Bytes
        +decode_xor_address(value, txn) Result
    }
    class TurnModule {
        <<module>>
        +encode_lifetime(secs) Bytes
        +decode_lifetime(value) Result
        +encode_channel_number(channel) Bytes
        +decode_channel_number(value) Result
        +is_channel_data(buf) bool
        +parse_channel_data(data) Result
        +encode_channel_data(channel, payload) Bytes
        +error_code(err) tuple
        +error_response(method, txn, err) Bytes
        +error_response_with(method, txn, err, extra) Bytes
    }
    class CodecError {
        <<enumeration>>
        TooShort
        BadHeader
        BadMagicCookie
        BadLength
        BadAttribute
        BadFingerprint
        BadAddress
    }
    StunMessage "1" *-- "0..*" Attribute : съдържа
    StunMessage --> MessageClass
    StunMessage ..> CodecError : parse връща
    StunModule ..> StunMessage
    TurnModule ..> StunMessage : строи отговори
    TurnModule ..> CodecError
```

| Тип | Бележка |
|-----|---------|
| `MessageClass` | В кода се казва `Class` |
| `bytes12` | `[u8; 12]`, идентификатор на транзакцията |
| `Attribute.value` | `Bytes`: при `parse` е срез на входния datagram (без копиране) |
| `encode_with_integrity` | Добавя MESSAGE-INTEGRITY (HMAC-SHA1) преди незадължителния FINGERPRINT |

## 2.2 Транспорт, контрол и registry (`transport`, `registry`)

```mermaid
classDiagram
    direction LR
    class Transport {
        -ControlCtx ctx
        -UdpSocket socket
        -RegistryHandle registry
        -Metrics metrics
        -Semaphore control_slots
        +new(ctx) Transport
        +run(shutdown) Result
    }
    class Outcome {
        <<enumeration>>
        Reply
        Turn
        ChannelData
        Drop
    }
    class ControlCtx {
        +UdpSocket socket
        +RegistryHandle registry
        +Telemetry telemetry
        +HmacAuth auth
        +u32 default_lifetime_secs
        +PeerPolicy peer_policy
        +new(cfg, socket, registry, telemetry) ControlCtx
        -check_peer(client_addr, ip) Result
    }
    class ControlModule {
        <<module>>
        +handle_request(ctx, msg, raw, src)
        +handle_send_indication(registry, metrics, msg, src)
        +handle_channel_data(registry, metrics, channel, payload, src)
    }
    class RegistryHandle {
        -Sender tx
        -DashMap routes
        +lookup(client_addr) Option
        +allocate(client_addr, user_id, lifetime) Result
        +shutdown_all()
    }
    class RegistryActor {
        -RegistryConfig cfg
        -Receiver cmd_rx
        -Receiver event_rx
        -DashMap routes
        -HashMap allocs
        -HashMap per_user
        -HashSet in_use_ports
        -u16 next_port
        -u64 next_id
        +run()
        -allocate(client_addr, username, requested) Result
        -bind_relay_socket() Option
        -on_event(event)
        -shutdown_all()
    }
    class AllocRecord {
        +SocketAddr client_addr
        +String username
        +u16 port
        +AllocationHandle handle
    }
    class AllocationHandle {
        +AllocationId id
        +Sender tx
        +Arc user_id
    }
    class AllocationInfo {
        +AllocationId id
        +SocketAddr relayed_addr
        +u32 lifetime_secs
    }
    Transport o-- ControlCtx
    Transport ..> Outcome : handle_datagram
    Transport ..> ControlModule : spawn / вика
    ControlModule ..> ControlCtx
    ControlCtx --> RegistryHandle
    ControlCtx --> HmacAuth
    ControlCtx --> PeerPolicy
    ControlCtx --> Telemetry
    RegistryHandle ..> RegistryActor : RegistryCmd през mpsc
    RegistryHandle o-- AllocationHandle : routes
    RegistryActor "1" *-- "0..*" AllocRecord
    AllocRecord --> AllocationHandle
    RegistryActor ..> AllocationInfo : връща
```

| Поле | Значение |
|------|----------|
| `routes` | Общ `Arc<DashMap>` от клиентски адрес към `AllocationHandle`; пише го `RegistryActor`, четат го `Transport` и `control` |
| `allocs` | `HashMap` от `AllocationId` към `AllocRecord` (собственост на registry) |
| `per_user` | `HashMap` от `user_id` към брой активни allocation-и (квота) |
| `in_use_ports` | `HashSet` от заети релейни портове |
| `AllocationHandle.user_id` | Собственикът на allocation-а; ползва се за проверка на `Refresh`/`CreatePermission`/`ChannelBind` |

## 2.3 Allocation actor (`allocation`)

```mermaid
classDiagram
    direction LR
    class AllocationParams {
        +AllocationId id
        +SocketAddr client_addr
        +String username
        +UdpSocket relayed
        +UdpSocket main_socket
        +u32 lifetime_secs
        +Receiver cmd_rx
        +Sender events
        +Metrics metrics
    }
    class AllocationActor {
        -AllocationId id
        -SocketAddr client_addr
        -UdpSocket relayed
        -UdpSocket main_socket
        -Receiver cmd_rx
        -Instant expires_at
        -HashMap permissions
        -HashMap channels
        -HashMap peer_channels
        -u64 bytes_relayed
        -u32 seq
        +event_loop()
        -on_cmd(cmd) bool
        -add_permission(ip) Result
        -bind_channel(channel, peer) Result
        -peer_for_channel(channel) Option
        -channel_for_peer(peer) Option
        -permitted(ip) bool
        -send_to_peer(peer, payload)
        -on_peer_packet(data, from)
    }
    class AllocationModule {
        <<module>>
        +run(params)
        +PERMISSION_LIFETIME 300s
        +CHANNEL_LIFETIME 600s
    }
    class AllocationHandle {
        +AllocationId id
        +Sender tx
        +Arc user_id
    }
    AllocationModule ..> AllocationParams : получава
    AllocationModule ..> AllocationActor : създава и пуска
    AllocationHandle ..> AllocationActor : AllocationCmd през mpsc
    AllocationActor ..> RegistryActor : RegistryEvent AllocationClosed
```

| Поле на `AllocationActor` | Съдържание |
|---------------------------|------------|
| `permissions` | `IpAddr` към момент на изтичане (до 256 записа) |
| `channels` | номер на канал към (peer адрес, изтичане), до 128 записа |
| `peer_channels` | обратен индекс: peer адрес към номер на канал |
| `expires_at` | краен срок на allocation-а; `Refresh` го мести |
| `seq` | брояч за уникален transaction id на Data indication |

## 2.4 Съобщения между actor-ите (`types`)

```mermaid
classDiagram
    direction LR
    class AllocationCmd {
        <<enumeration>>
        Refresh
        CreatePermission
        ChannelBind
        SendToPeer
        SendOnChannel
        Shutdown
    }
    class RegistryCmd {
        <<enumeration>>
        Allocate
        ShutdownAll
    }
    class RegistryEvent {
        <<enumeration>>
        AllocationClosed
    }
    class TelemetryEvent {
        <<enumeration>>
        AllocationOpened
        AllocationClosed
        PolicyBlocked
    }
    class TurnError {
        <<enumeration>>
        BadRequest
        Unauthorized
        StaleNonce
        AllocationMismatch
        ForbiddenPeer
        QuotaExceeded
        InsufficientCapacity
        InternalError
    }
    RegistryCmd ..> TurnError : отговор през oneshot
    AllocationCmd ..> TurnError : отговор през oneshot
```

| Съобщение | Полета | Отговор |
|-----------|--------|---------|
| `AllocationCmd::Refresh` | `lifetime_secs`, `reply` | `oneshot<u32>`: даденият lifetime; `0` затваря allocation-а |
| `AllocationCmd::CreatePermission` | `peer_ip`, `reply` | `oneshot<Result>` |
| `AllocationCmd::ChannelBind` | `channel`, `peer_addr`, `reply` | `oneshot<Result>` |
| `AllocationCmd::SendToPeer` | `peer_addr`, `payload` | няма (`try_send`, при пълна опашка пакетът се пуска) |
| `AllocationCmd::SendOnChannel` | `channel`, `payload` | няма |
| `RegistryCmd::Allocate` | `client_addr`, `username` (user_id), `requested_lifetime_secs`, `reply` | `oneshot<Result<AllocationInfo>>` |
| `RegistryCmd::ShutdownAll` | `reply` | `oneshot<()>` |
| `RegistryEvent::AllocationClosed` | `allocation_id`, `client_addr`, `username`, `bytes_relayed` | няма |

## 2.5 Автентикация, политика, конфигурация и грешки (`auth`, `config`, `error`)

```mermaid
classDiagram
    direction LR
    class HmacAuth {
        -bytes secret
        -String realm
        -List algos
        -u64 grace_secs
        +new(secret, realm) HmacAuth
        +with_algos(algos) HmacAuth
        +with_grace_secs(secs) HmacAuth
        +password_for(username) String
        +password_for_algo(username, algo) String
        +issue_credentials(user_id, expiry) tuple
        +make_nonce(now) String
        +check_nonce(nonce, now) bool
        +challenge(now) List
        +authenticate(msg, raw, now) Result
        +authenticate_session(msg, raw, now, owner) Result
    }
    class HmacAlgo {
        <<enumeration>>
        Sha1
        Sha256
    }
    class Authenticated {
        +String user_id
        +bytes16 key
    }
    class PeerPolicy {
        +bool allow_private
        +List allowed
        +List denied
        +check(ip) Option
    }
    class IpRange {
        <<enumeration>>
        V4
        V6
        +contains(ip) bool
    }
    class Config {
        +SocketAddr listen_addr
        +Option external_ip
        +u16 relay_min_port
        +u16 relay_max_port
        +usize max_allocations
        +usize max_allocations_per_user
        +u32 allocation_lifetime_secs
        +String auth_secret
        +List auth_algos
        +u64 credential_grace_secs
        +String realm
        +bool allow_private_peers
        +List allowed_peer_ips
        +List denied_peer_ips
        +usize channel_cap
        +Option metrics_addr
        +from_env() Result
        +from_lookup(get) Result
        +effective_max_allocations() usize
    }
    class ConfigError {
        <<enumeration>>
        Invalid
    }
    HmacAuth o-- HmacAlgo : приема
    HmacAuth ..> Authenticated : връща
    PeerPolicy o-- IpRange : allowed и denied
    Config o-- HmacAlgo
    Config o-- IpRange
    Config ..> ConfigError
    Config ..> HmacAuth : ControlCtx я строи от Config
    Config ..> PeerPolicy : ControlCtx я строи от Config
```

`TurnError` и `CodecError` са в [2.1](#21-протоколен-слой-protocolstun-protocolturn) и [2.4](#24-съобщения-между-actor-ите-types). `Config` има ръчна `Debug` реализация, която скрива `auth_secret`.

## 2.6 Telemetry (`telemetry`)

```mermaid
classDiagram
    direction LR
    class Telemetry {
        -Sender tx
        -Metrics metrics
        +spawn(capacity) tuple
        +emit(event)
        +metrics() Metrics
    }
    class Metrics {
        +AtomicUsize active_allocations
        +AtomicU64 total_relayed_bytes
        +AtomicU64 dropped_packets
        +AtomicU64 dropped_events
        +AtomicU64 allocations_total
        +AtomicU64 auth_failures
        +AtomicU64 policy_blocked
        +render_prometheus() String
    }
    class HttpModule {
        <<module>>
        +serve(listener, metrics, shutdown)
    }
    Telemetry "1" *-- "1" Metrics
    HttpModule ..> Metrics : чете
    Telemetry ..> TelemetryEvent : приема
```

`Telemetry::emit` никога не блокира: при пълен канал събитието се пуска и `dropped_events` расте. Броячите са атомни (`Relaxed`) и се четат без заключване.

## 2.7 Инструмент за натоварване (`loadtest`)

```mermaid
classDiagram
    direction LR
    class Params {
        +SocketAddr server
        +String secret
        +String realm
        +HmacAlgo algo
        +IpAddr peer_ip
        +u32 clients
        +u32 seconds
        +u32 pps
        +usize payload
    }
    class Report {
        +u32 clients_ok
        +u32 clients_failed
        +u64 sent
        +u64 received
        +List rtts_us
        +print(params)
    }
    class ClientResult {
        +u64 sent
        +List rtts_us
    }
    class Creds {
        -String username
        -bytes16 key
        -String realm
        -String nonce
        +request(txn, method, attributes) Bytes
    }
    Params ..> Report : run_with връща
    Report o-- ClientResult : обобщава
    ClientResult ..> Creds : всеки клиент има свои
```

## 2.8 Връзки между типовете (обобщено)

```mermaid
flowchart LR
    Config --> ControlCtx
    Config --> RegistryActor
    ControlCtx --> HmacAuth
    ControlCtx --> PeerPolicy
    ControlCtx --> RegistryHandle
    ControlCtx --> Telemetry
    RegistryHandle -->|"RegistryCmd"| RegistryActor
    RegistryActor -->|"spawn + AllocationParams"| AllocationActor
    RegistryHandle -->|"routes: DashMap"| AllocationHandle
    AllocationHandle -->|"AllocationCmd"| AllocationActor
    AllocationActor -->|"RegistryEvent"| RegistryActor
    RegistryActor --> Telemetry
```
