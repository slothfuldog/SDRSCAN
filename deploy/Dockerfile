# SDRScan: one image with the backend (web UI embedded), sdrscan-sast, sdrscan-dast, git and ssh.
# Build from the repository root:  docker build -f deploy/Dockerfile -t sdrscan .
FROM rust:1 AS engines
WORKDIR /src
COPY engine/Cargo.toml engine/Cargo.lock ./
COPY engine/crates ./crates
RUN cargo build --release -p sdrscan-sast -p sdrscan-dast -p sdrscan-vuln

FROM node:lts AS web
WORKDIR /web
COPY frontend/ ./
RUN npm ci && npx nuxt generate

FROM golang:1 AS backend
WORKDIR /app
COPY backend/ ./
# The generated site is embedded into the binary (internal/webui/dist).
RUN rm -rf internal/webui/dist && mkdir -p internal/webui/dist
COPY --from=web /web/.output/public/ ./internal/webui/dist/
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=0.1.0" -o /out/sdrscan-backend ./cmd/sdrscan-backend

FROM debian:stable-slim
RUN apt-get update && apt-get install -y --no-install-recommends git openssh-client ca-certificates \
 && rm -rf /var/lib/apt/lists/* && useradd -r -u 10001 sdrscan && mkdir /work && chown sdrscan /work
COPY --from=engines /src/target/release/sdrscan-sast /src/target/release/sdrscan-dast /src/target/release/sdrscan-vuln /usr/local/bin/
COPY --from=backend /out/sdrscan-backend /usr/local/bin/
COPY engine/templates /opt/sdrscan/templates
COPY engine/profiles /opt/sdrscan/profiles
USER sdrscan
EXPOSE 8080
ENTRYPOINT ["sdrscan-backend", "serve"]
