# 1. Архитектура

## 1.1 Цел и обхват

Релеят позволява на два клиента зад NAT да обменят медия, когато директна връзка (ICE) не е възможна. Поддържа:

- STUN Binding (откриване на публичния адрес);
- TURN Allocate, Refresh, CreatePermission, ChannelBind;
- Send/Data indication и ChannelData (релеиране на данни);
- time-limited HMAC credentials, IP политика срещу SSRF, лимити и метрики.

Извън обхвата: TURN-over-TCP, TLS/DTLS, външна база с потребители.

## 1.2 Системен контекст

```mermaid
flowchart LR
    A["Клиент A<br/>WebRTC приложение"]
    B["Клиент B / peer<br/>WebRTC приложение"]
    BE["Messenger backend"]
    R["stun-turn-relay"]
    P["Prometheus"]

    BE -- "1. username + password + realm<br/>HMAC, ограничен TTL" --> A
    A -- "2. STUN / TURN през UDP 3478" --> R
    R -- "3. UDP от релейните портове" --> B
    B -- "4. медия към relayed адреса" --> R
    R -- "5. Data indication / ChannelData" --> A
    P -- "GET /metrics" --> R
    BE -. "споделен AUTH_SECRET" .- R
```

Backend-ът и релеят **не си говорят** по мрежата. Те споделят само `AUTH_SECRET`; релеят проверява credentials без база данни.

## 1.3 Компоненти

```mermaid
flowchart TB
    subgraph proc["Процес stun-turn-relay - един tokio runtime"]
        subgraph tr["transport"]
            UDP["udp::Transport<br/>recv цикъл и demux"]
            CTL["control::handle_request<br/>Allocate, Refresh,<br/>CreatePermission, ChannelBind"]
            FAST["control::handle_send_indication<br/>control::handle_channel_data"]
        end
        subgraph pr["protocol"]
            STUN["stun<br/>кодек, XOR адреси, FINGERPRINT,<br/>MESSAGE-INTEGRITY"]
            TURN["turn<br/>константи, ChannelData,<br/>кодове за грешки"]
        end
        subgraph au["auth"]
            HMAC["hmac_auth<br/>credentials, nonce, проверка на MI"]
            POL["policy<br/>забранени peer IP-та"]
        end
        REG["registry::RegistryActor<br/>допускане, квоти, порт-пул"]
        ALLOC["allocation::AllocationActor<br/>един task на allocation"]
        subgraph te["telemetry"]
            TEL["Telemetry<br/>събития и атомни броячи"]
            HTTP["http::serve<br/>/metrics и /healthz"]
        end
        CFG["config::Config"]
    end

    UDP --> STUN
    UDP --> TURN
    UDP -- "Reply / Turn" --> CTL
    UDP -- "ChannelData / Send" --> FAST
    CTL --> HMAC
    CTL --> POL
    CTL -- "Allocate" --> REG
    CTL -- "AllocationCmd" --> ALLOC
    FAST -- "AllocationCmd" --> ALLOC
    REG -- "spawn" --> ALLOC
    ALLOC -- "RegistryEvent" --> REG
    REG --> TEL
    CTL --> TEL
    HTTP --> TEL
    CFG --> REG
    CFG --> CTL
```

Отговорности:

| Модул | Отговорност | Състояние |
|-------|-------------|-----------|
| `transport::udp` | Чете сокета, класифицира датаграмите, праща бързите пътища директно | Без споделено състояние |
| `transport::control` | Автентикира и изпълнява TURN заявки | Без състояние (`ControlCtx` е само за четене) |
| `registry` | Лимити, порт-пул, жизнен цикъл на allocation-и | Притежава се от един actor |
| `allocation` | Permissions, channels, lifetime, релеене | Притежава се от един actor на allocation |
| `auth` | Credentials, nonce, MESSAGE-INTEGRITY, IP политика | Чисти функции + secret |
| `telemetry` | Броячи и логове | Атомни стойности + bounded канал |

## 1.4 Зависимости между модулите

```mermaid
flowchart LR
    main --> config
    main --> transport
    main --> registry
    main --> telemetry
    main --> loadtest
    transport --> protocol
    transport --> auth
    transport --> registry
    transport --> telemetry
    registry --> allocation
    registry --> config
    registry --> telemetry
    registry --> types
    allocation --> protocol
    allocation --> types
    allocation -. "MAX_DATAGRAM" .-> transport
    protocol -. "message_integrity" .-> auth
    auth --> protocol
    transport --> types
    types --> error
    protocol --> error
```

Пунктирните стрелки са две известни неточности в слоевете (рефакторинг за по-късно, без промяна на поведението):

1. `allocation` взема константата `MAX_DATAGRAM` от `transport::udp`;
2. `protocol::stun` вика `auth::hmac_auth::message_integrity` при кодиране с MESSAGE-INTEGRITY, а `auth` ползва `protocol` - има цикъл между двата модула. Криптографската функция може да се премести в отделен модул.

## 1.5 Модел на конкурентност

Идея: **без mutex-и по горещите пътища**. Състоянието има един собственик, а общуването е през bounded канали.

```mermaid
flowchart TB
    SOCK(("UDP сокет :3478"))
    subgraph T1["task: Transport.run"]
        LOOP["recv_from цикъл"]
    end
    subgraph T2["tasks: control заявки, до 1024 едновременно"]
        H["handle_request"]
    end
    subgraph T3["task: RegistryActor"]
        RA["allocate, on_event, shutdown_all"]
    end
    subgraph T4["tasks: AllocationActor, по един на allocation"]
        AA["select: lifetime таймер,<br/>команди, пакети от peer"]
    end
    subgraph T5["task: telemetry consumer"]
        TC["логва събитията"]
    end
    subgraph T6["task: metrics http, по избор"]
        MH["GET /metrics"]
    end
    DM[("DashMap<br/>client_addr към AllocationHandle")]

    SOCK --> LOOP
    LOOP -- "spawn + Semaphore 1024" --> H
    LOOP -- "try_send SendToPeer / SendOnChannel" --> AA
    H -- "mpsc 256: RegistryCmd + oneshot" --> RA
    H -- "mpsc CHANNEL_CAP + oneshot" --> AA
    RA -- "spawn" --> AA
    AA -- "mpsc 1024: RegistryEvent" --> RA
    RA -- "insert / remove_if" --> DM
    LOOP -- "lookup" --> DM
    H -- "lookup" --> DM
    RA -- "try_send, mpsc 1024" --> TC
    AA -- "peer към клиента: send_to през главния сокет" --> SOCK
```

Правила:

- **Горещ път** (`ChannelData`, `Send`): един lookup в `DashMap`, един `try_send`, без копиране на payload-а (`Bytes::slice`). Ако опашката е пълна, пакетът се пуска (`dropped_packets`), а не се буферира.
- **Контролен път** (Allocate, Refresh, ...): отделен task на заявка, ограничен със `Semaphore(1024)`.
- **Peer към клиент**: `AllocationActor` праща директно през главния сокет, без междинен hop.
- **Shutdown**: `watch<bool>` спира `Transport`, после `RegistryCmd::ShutdownAll` затваря allocation-ите.

Размерите на опашките и останалите лимити са в `README.md` (конфигурация) и в [Замяна на coturn](06-coturn-migration.md#66-точка-5-политика-за-peer-адреси-и-лимити).

## 1.6 Данни в паметта

```mermaid
erDiagram
    ROUTES_INDEX {
        string client_addr PK
        u64 allocation_id FK
    }
    ALLOC_RECORD {
        u64 allocation_id PK
        string client_addr UK
        string user_id
        u16 relay_port UK
    }
    ALLOCATION_STATE {
        u64 allocation_id PK
        instant expires_at
        u64 bytes_relayed
        u32 seq
    }
    PERMISSION {
        string peer_ip PK
        instant expires_at
    }
    CHANNEL_BINDING {
        u16 channel PK
        string peer_addr UK
        instant expires_at
    }

    ROUTES_INDEX ||--|| ALLOC_RECORD : "огледало в DashMap"
    ALLOC_RECORD ||--|| ALLOCATION_STATE : "един actor"
    ALLOCATION_STATE ||--o{ PERMISSION : "най-много 256"
    ALLOCATION_STATE ||--o{ CHANNEL_BINDING : "най-много 128"
```

| Структура | Къде живее | Собственик |
|-----------|-----------|------------|
| `ROUTES_INDEX` | `Arc<DashMap>` в `RegistryHandle` | Пише `RegistryActor`, четат `Transport` и `control` |
| `ALLOC_RECORD`, `per_user`, `in_use_ports` | Полета на `RegistryActor` | `RegistryActor` |
| `ALLOCATION_STATE`, `PERMISSION`, `CHANNEL_BINDING` | Полета на `AllocationActor` | Съответният `AllocationActor` |

Инварианти:

- един allocation на клиентски адрес (иначе 437);
- един порт на allocation; портът се освобождава едва след `AllocationClosed`;
- един peer адрес е вързан най-много към един канал и обратно;
- `routes` се чисти с `remove_if`, само ако записът още сочи към същия allocation.

## 1.7 Deployment

```mermaid
flowchart LR
    NET(("Internet"))
    subgraph host["Docker host"]
        FW["Firewall:<br/>UDP 3478 и 49152-49352"]
        subgraph ctr["контейнер relay<br/>distroless, non-root, read-only, cap_drop ALL"]
            BIN["stun-turn-relay"]
        end
        MET["127.0.0.1:9100<br/>/metrics, само вътрешно"]
    end
    NET --> FW --> BIN
    BIN -. "по избор: METRICS_ADDR" .-> MET
```

- Публикуваният диапазон трябва да съвпада с `RELAY_MIN_PORT..RELAY_MAX_PORT`.
- `EXTERNAL_IP` е публичният адрес на хоста; той влиза във всеки `XOR-RELAYED-ADDRESS`.
- На Linux с висок трафик е по-добре `network_mode: host` (без Docker NAT за UDP).

## 1.8 Ключови архитектурни решения

| Решение | Причина | Компромис |
|---------|---------|-----------|
| Actor-и вместо споделено състояние с mutex | Няма lock contention, ясна собственост | Нужни са съобщения и опашки |
| `DashMap` за маршрутизация | Горещият път не минава през registry | Две места за истината (registry и map) - синхронизират се със събития |
| Stateless credentials и nonce | Няма база, лесно мащабиране | Няма отмяна преди `expiry` |
| `Bytes` zero-copy за Send/ChannelData | Малко копиране и алокации | Datagram-ът се копира веднъж при приемане |
| Bounded опашки + `try_send` | Предвидима памет, защита от претоварване | Пакети се губят при пренатоварване (приемливо за real-time медия) |
| Директно изпращане от allocation actor | По-малко hop-ове | Actor-ът знае за главния сокет |
| Без външни HTTP/крипто фреймуърци освен RustCrypto | Малка повърхност | Собствен минимален HTTP за метриките |
