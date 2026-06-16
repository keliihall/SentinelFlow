FROM rust:1.85-bookworm AS builder

WORKDIR /src
COPY . .
RUN cargo build --release -p sentinelflow-api -p sentinelflow-cli

FROM rust:1.85-bookworm AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /src/target/release/sentinelflow-api /usr/local/bin/sentinelflow-api
COPY --from=builder /src/target/release/sentinelflow /usr/local/bin/sentinelflow
COPY schemas ./schemas
COPY plugins/examples ./plugins/examples
COPY docs ./docs

ENV SENTINELFLOW_API_BIND=0.0.0.0:8080
ENV SENTINELFLOW_WORKSPACE_DIR=/data/.sentinelflow
ENV SENTINELFLOW_SCHEMA_ROOT=/app

EXPOSE 8080
VOLUME ["/data"]

CMD ["sentinelflow-api"]
