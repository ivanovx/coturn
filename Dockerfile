# syntax=docker/dockerfile:1

# ---- build stage: cache dependencies first ----
FROM rust:1-slim-bookworm AS build
WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
RUN mkdir src \
 && echo 'fn main() {}' > src/main.rs \
 && cargo build --release \
 && rm -rf src
COPY src ./src
RUN touch src/main.rs && cargo build --release

# ---- runtime stage: distroless, non-root, no shell ----
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /app/target/release/stun-turn-relay /usr/local/bin/stun-turn-relay
# 65532:65532 ("nonroot"); ports are > 1024, so no capabilities are needed.
USER nonroot
EXPOSE 3478/udp
ENTRYPOINT ["/usr/local/bin/stun-turn-relay"]
