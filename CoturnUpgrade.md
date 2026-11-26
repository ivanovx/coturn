# Препоръки за развитие на Coturn проекта

## Обхват

Този документ разглежда собствения Rust проект [`stun-turn-relay`](https://github.com/ivanovx/coturn/tree/main/stun-turn-relay), който замества Coturn в Telex. Целта не е пълна съвместимост с всички функции на upstream Coturn, а надежден TURN relay за реалните нужди на Telex.

Проектът в момента е UDP-only и поддържа основните STUN/TURN операции, HMAC credentials, peer IP политики, квоти, метрики и Docker deployment. Приоритетите по-долу са подредени така, че първо да се потвърди реалната работа и едва след това да се разширяват функциите и капацитетът.

## Приоритет 1: Потвърждаване на работоспособността

### 1. CI и проверен статус на проекта

Настрой автоматичен pipeline за всяка промяна, който изпълнява:

- `cargo fmt --check`
- `cargo clippy`
- `cargo test`
- Docker image build
- кратък smoke test на контейнера

След като тези проверки минават, обнови README. Там все още има бележка, че проектът не е бил компилиран и тестван от автора. Документацията трябва да отразява провереното състояние, а не първоначалната спецификация.

### 2. Интеграционен тест с Telex и реален WebRTC клиент

Добави staging сценарий, който проверява:

- че backend-ът и relay-ът издават и приемат еднакви credentials;
- че клиентът получава relay ICE candidate;
- че разговорът работи с принудително relay, а не само през директен peer-to-peer път;
- че `Allocate`, `Refresh`, permissions и ChannelData работят в реален разговор;
- че разговорът продължава през подновяване на allocation-а и изтичане на credentials;
- че клиентът може да се възстанови след загуба на мрежа или промяна на NAT адреса.

Локалните тестове са полезни, но не доказват съвместимост с браузърите, реалните NAT-и или мобилни и корпоративни мрежи. Виж [оперативни тестове](https://github.com/ivanovx/coturn/blob/main/docs/05-operations-testing.md) и [плана за Coturn миграция](https://github.com/ivanovx/coturn/blob/main/docs/06-coturn-migration.md).

## Приоритет 2: Капацитет и наблюдаемост

### 3. Измерване и настройване на капацитета

В текущата конфигурация на Telex диапазонът `49160–49200` съдържа 41 UDP relay порта. Понеже всеки allocation използва един порт, това ограничава услугата до 41 едновременни allocations — приблизително 20 разговори 1:1, ако всеки участник използва по един allocation.

Преди production натоварване:

- измери очаквания брой едновременни разговори и allocations на потребител;
- увеличи `RELAY_MIN_PORT`/`RELAY_MAX_PORT` и публикувания Docker диапазон според нуждата;
- подравни `MAX_ALLOCATIONS` с реалния брой портове;
- проведи `loadtest` от отделна машина и измери CPU, памет, bandwidth, загубени пакети и latency;
- остави капацитетен резерв за пикове и временни повторни allocations.

Не оптимизирай packet path преди да има измервания, които показват къде е bottleneck-ът.

### 4. Мониторинг и аларми

Проектът вече предоставя Prometheus метрики. Настрой scrape и аларми за:

- активни allocations, особено при приближаване до лимита;
- неуспешна автентикация;
- отхвърлени пакети и telemetry събития;
- блокирани peer адреси;
- релеиран трафик и внезапни промени в него;
- неуспешен health check или рестарт на контейнера.

Metrics endpoint-ът няма автентикация. Излагай го само във вътрешна мрежа или върху loopback интерфейс; не го публикувай директно в интернет.

### 5. Production мрежова конфигурация

В production `EXTERNAL_IP` трябва да е адресът, достижим от клиентите, а не `127.0.0.1`. Отвори UDP listener порта и целия relay порт диапазон във firewall-а и ги препрати без промяна на номерата през NAT.

Провери отделно:

- че клиентът вижда правилния relay IP в ICE candidate;
- че relay портовете са достъпни от външна мрежа;
- че Docker/host firewall не блокира UDP;
- че времето на backend-а, клиентите и relay-а е синхронизирано.

## Приоритет 3: Покритие и сигурност

### 6. Решение за TCP/TLS fallback

Текущият relay поддържа UDP, но не TURN-over-TCP или TURN-over-TLS. Първо измери чрез WebRTC статистиките колко клиенти действително се нуждаят от TCP/TLS relay.

- Ако случаите са редки, запази UDP-only реализацията и документирай ограничението.
- Ако има съществен дял клиенти зад мрежи, които блокират UDP, използвай отделен Coturn deployment като TCP/TLS fallback със същия realm и съвместими credentials.
- Разработвай TCP/TLS вътре в `stun-turn-relay` само ако единна услуга оправдава допълнителната сложност и има тестове за нея.

Това решение не бива да се базира само на пълната feature-листa на Coturn, а на наблюдаваните нужди на потребителите.

### 7. Secret rotation и abuse controls

Добави документирана процедура за ротация на `AUTH_SECRET`, включително период на припокриване, през който старите и новите credentials могат да се валидират. Запази интеграционен тест за HMAC-SHA1 режим, който използва Telex за Coturn съвместимост.

Като следващи защитни подобрения обмисли:

- rate limiting на неавтентикирани заявки;
- лимити за bandwidth или брой bytes на allocation;
- аларми при необичайни auth failures или трафик;
- проверка и периодичен преглед на `ALLOWED_PEER_IPS` и `DENIED_PEER_IPS`.

Не изключвай вградените забрани за private/loopback адреси в production без конкретна, документирана причина.

### 8. IPv6 и допълнителни мрежови сценарии

Провери end-to-end IPv6 работа с реални клиенти и dual-stack deployment. Ако има потребителско търсене, добави тестове за IPv6 relay адреси, firewall правила и IPv4-mapped IPv6 адреси. Направи това след основните проверки на UDP и капацитета, за да остане обхватът управляем.

## Приоритет 4: Версиониране и release процес

### 9. Версионирани Docker образи

За staging и production публикувай versioned image tags вместо да разчиташ само на локалния `stun-turn-relay:latest`. Автоматизирай:

- build и тестове при release;
- сканиране на зависимости и container image;
- SBOM и build provenance;
- deployment към staging с последващ smoke test;
- rollback към предишен versioned image.

Контейнерът вече е проектиран с non-root потребител и минимални права; запази тези ограничения в deployment конфигурацията.

## Препоръчителен ред за изпълнение

1. CI: format, clippy, tests и Docker build.
2. Реален WebRTC smoke test с Telex и принудителен relay.
3. Измерване на натоварването и определяне на нужния relay port range.
4. Metrics, health checks и аларми в staging.
5. Проверка на production IP, firewall и NAT конфигурацията.
6. Решение за TCP/TLS въз основа на реални client stats.
7. Secret rotation, abuse controls, IPv6 и versioned releases според резултатите.

## Източници

- [Проектът `stun-turn-relay`](https://github.com/ivanovx/coturn/tree/main/stun-turn-relay)
- [Оперативни инструкции и тестове](https://github.com/ivanovx/coturn/blob/main/docs/05-operations-testing.md)
- [Разлики и миграция от Coturn](https://github.com/ivanovx/coturn/blob/main/docs/06-coturn-migration.md)
