# Разлики спрямо текущия coturn

Цел: да обсъдим какво е необходимо, преди този сървър да замени coturn в проекта за разговори.
Сравнението е по предоставената Docker конфигурация; реалният backend и клиентите още не са проверени.

## 1. Временни TURN credentials

- Coturn с `--use-auth-secret` използва `base64(HMAC-SHA1(secret, username))` за временната парола.
- Този сървър използва `base64(HMAC-SHA256(secret, username))`. Еднакъв secret не е достатъчен: паролите се различават и удостоверяването с coturn credentials ще се провали.
- За обсъждане: съвместим режим с HMAC-SHA1 или промяна на backend-а. Да се провери реалният формат на username и генераторът на credentials.

Източници: [coturn TURN REST API](https://github.com/coturn/coturn/blob/4.6.3/README.turnserver#turn-rest-api), [hmac_auth.rs](./src/auth/hmac_auth.rs).

## 2. TURN-over-TCP

- Текущият coturn публикува UDP и TCP listener на TURN порта.
- Този сървър приема само UDP. Клиентите, които се свързват към TURN сървъра през TCP, няма да могат да го използват.
- За обсъждане: необходим ли е TCP fallback за целевите мрежи и клиенти? TURN-over-TCP е отделно от TCP relay между сървъра и peer-а.

Източник: [README на сървъра](./src/README.md).

## 3. Изтичане на credentials и продължителни разговори

- Този сървър проверява срока на credentials при всяка удостоверена TURN заявка, включително Refresh. След изтичането им обновяването на allocation може да бъде отхвърлено.
- Coturn описва запазване на първоначалната парола за поддържана сесия след изтичането ѝ.
- За обсъждане: срокът на credentials, обновяването им от приложението и очакваното поведение при дълги разговори. Необходимо е тестване с реалните клиенти.

Източници: [hmac_auth.rs](./src/auth/hmac_auth.rs), [coturn TURN REST API](https://github.com/coturn/coturn/blob/4.6.3/README.turnserver#turn-rest-api).

## 4. Docker и мрежови настройки

- Настройките имат еквиваленти: `REALM=telex`, `AUTH_SECRET` със същия shared secret, `LISTEN_ADDR` с избрания TURN порт и `RELAY_MIN_PORT=49160` / `RELAY_MAX_PORT=49200`.
- Текущият [compose.yaml](./compose.yaml) публикува друг фиксиран relay диапазон и порт `3478`; трябва да се адаптира така, че публикуваните UDP портове да съвпадат с конфигурацията.
- При Docker/NAT трябва да се зададе достижимият от peer-ите `EXTERNAL_IP`, а relay портовете да се препращат със същите номера. TCP mapping сам по себе си няма да добави TCP поддръжка.

## 5. Политика за peer адреси и ограничения

- Новият сървър блокира посочените в coturn конфигурацията частни, loopback и link-local IPv4 адреси и multicast. Блокира и допълнителни адреси, включително IPv6 ULA и link-local. Това може да промени поведението в локални или IPv6 мрежи.
- Има собствени ограничения, включително максимум 2048 байта на входящ UDP datagram, 2000 allocations глобално и 16 на потребител по подразбиране. Да се проверят спрямо реалния трафик и натоварване.
- `ALLOW_PRIVATE_PEERS=true` е предназначено само за разработка; не е еквивалентно на фините `--denied-peer-ip` правила.

Източници: [policy.rs](./src/auth/policy.rs), [config.rs](./src/config.rs), [udp.rs](./src/transport/udp.rs).

## Проверка преди замяна

Локалните тестове минават, но не доказват съвместимост с външния backend и реалните WebRTC клиенти. След избора на решения са нужни интеграционни тестове за credentials, UDP relay, дълъг разговор и, ако е необходим, TCP fallback.
