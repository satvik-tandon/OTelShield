# OTelShield

Privacy-preserving OpenTelemetry gateway that scrubs sensitive telemetry before it leaves your network.

## MVP components

- Custom OpenTelemetry Collector distribution with a `redactprocessor`.
- Serverless control plane (API Gateway + Lambda + DynamoDB) for policy storage.
- Local demo stack with Jaeger + Prometheus + Grafana.

## Redaction rules (MVP)

- Drop secrets: `http.request.header.authorization`, `http.request.header.cookie`, `db.statement`.
- Mask emails in logs/attributes using regex.
- Tokenize user identifiers with HMAC (`enduser.id`, `user.id`, `customer.id`).

## Quick start (local demo)

1) Build and run the stack:

```bash
cd deploy
docker compose up --build
```

2) Trigger telemetry:

```bash
curl -i http://localhost:8080/checkout
```

3) Verify outputs:

- Collector logs show redacted fields in stdout (`debug` exporter).
- Jaeger UI at `http://localhost:16686`.
- Prometheus at `http://localhost:9090`.
- Grafana at `http://localhost:3000`.

The sample app emits intentionally sensitive fields (emails, headers, user IDs) so you can confirm masking, drops, and HMAC tokenization are working.

## ocb quickstart

If you want a copy/paste ocb build + telemetrygen validation flow (including the release binary download option), see `docs/ocb-quickstart.md`.

## Project layout

```
collector/
  builder-config.yaml
  config/
    collector.yaml
    policy.yaml
  processors/redactprocessor/
controlplane/
  cmd/api/
  template.yaml
  Makefile
sample-app/
  main.go
  Dockerfile
deploy/
  docker-compose.yaml
  prometheus.yml
```

## Collector build (local)

The Docker build uses `ocb`. To build locally:

```bash
cd collector
go install go.opentelemetry.io/collector/cmd/builder@v0.143.0
builder --config builder-config.yaml
```

Note: `go install` installs the binary as `builder`. If you prefer `ocb`, symlink it:

```bash
ln -s "$HOME/go/bin/builder" "$HOME/go/bin/ocb"
```

## Control plane (AWS SAM)

```
cd controlplane
sam build
sam deploy --guided
```

API routes:

- `GET /tenants/{tenantId}/policy/active`
- `POST /tenants/{tenantId}/policy`
- `POST /tenants/{tenantId}/policy/simulate`

## Notes

- Update `collector/config/policy.yaml` to change redaction rules.
- `collector/config/collector.yaml` wires the processor into traces/metrics/logs pipelines.
- Sample app emits logs, traces, and metrics with intentionally sensitive fields.
