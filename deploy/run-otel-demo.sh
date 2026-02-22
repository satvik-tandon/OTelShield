#!/usr/bin/env bash
set -euo pipefail

DEMO_DIR="${DEMO_DIR:-/tmp/opentelemetry-demo}"
ENVOY_PORT="${ENVOY_PORT:-8081}"
OTELSHIELD_ENDPOINT="${OTELSHIELD_ENDPOINT:-http://host.docker.internal:4318}"

if ! command -v git >/dev/null; then
  echo "git is required" >&2
  exit 1
fi

if command -v docker-compose >/dev/null; then
  COMPOSE_CMD="docker-compose"
else
  COMPOSE_CMD="docker compose"
fi

if [ ! -d "$DEMO_DIR/.git" ]; then
  git clone https://github.com/open-telemetry/opentelemetry-demo.git "$DEMO_DIR"
fi
if [ ! -f "$DEMO_DIR/docker-compose.yml" ]; then
  rm -rf "$DEMO_DIR"
  git clone https://github.com/open-telemetry/opentelemetry-demo.git "$DEMO_DIR"
fi

cat >"$DEMO_DIR/src/otel-collector/otelcol-config-otelshield.yml" <<EOF
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318

processors:
  memory_limiter:
    check_interval: 1s
    limit_mib: 512
    spike_limit_mib: 128
  batch: {}

exporters:
  otlphttp/otelshield:
    endpoint: ${OTELSHIELD_ENDPOINT}
    tls:
      insecure: true

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [otlphttp/otelshield]
    metrics:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [otlphttp/otelshield]
    logs:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [otlphttp/otelshield]
EOF

cat >"$DEMO_DIR/src/otel-collector/otelcol-config-extras-empty.yml" <<'EOF'
receivers: {}
processors: {}
exporters: {}
service:
  pipelines: {}
EOF

cat >"$DEMO_DIR/docker-compose.override.yml" <<'EOF'
services:
  otel-collector:
    extra_hosts:
      - "host.docker.internal:host-gateway"
    depends_on: {}
EOF

cd "$DEMO_DIR"
services=$($COMPOSE_CMD config --services | grep -Ev "^(jaeger|grafana|prometheus|opensearch)$" | tr '\n' ' ')
OTEL_COLLECTOR_CONFIG=./src/otel-collector/otelcol-config-otelshield.yml \
OTEL_COLLECTOR_CONFIG_EXTRAS=./src/otel-collector/otelcol-config-extras-empty.yml \
JAEGER_UI_PORT=16687 \
JAEGER_GRPC_PORT=4319 \
GRAFANA_PORT=13000 \
PROMETHEUS_PORT=19090 \
ENVOY_PORT="$ENVOY_PORT" \
$COMPOSE_CMD up --no-deps --force-recreate --remove-orphans --detach $services

echo "OpenTelemetry Demo running:"
echo "  Web store: http://localhost:${ENVOY_PORT}/"
echo "  Jaeger UI: http://localhost:16686"
echo "  Load generator UI: http://localhost:${ENVOY_PORT}/loadgen/"
