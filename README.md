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

2) Trigger telemetry (recommended):

```bash
./run-otel-demo.sh
```

3) Verify outputs:

- Collector logs show redacted fields in stdout (`debug` exporter).
- Jaeger UI at `http://localhost:16686`.
- Prometheus at `http://localhost:9090`.
- Grafana at `http://localhost:3000`.
- Local control plane at `http://localhost:18080`.
- Control plane UI at `http://localhost:18080/ui/`.

The OpenTelemetry demo services emit high-volume traffic so you can validate masking, drops, tokenization, and audit event capture at realistic scale.

4) (Optional) Verify audit counters:

- Query:
  `GET http://localhost:18080/tenants/demo/audit?day=YYYY-MM-DD`
- Prometheus metric:
  `otelshield_audit_rule_total{tenant_id="demo"}`
- Grafana dashboard:
  `Dashboards -> OTelShield -> OTelShield Audit`

Each redaction rule reports counts by `ruleId` (from `rules[].id`; falls back to `type.N` if omitted).

The control plane UI also includes:
- Policy editor (`load` + `save`)
- Audit events table with filters
- Cursor-based pagination (`Load more`)
- Local filter persistence in browser storage

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
- `GET /tenants/{tenantId}/audit?day=YYYY-MM-DD`
- `POST /tenants/{tenantId}/audit/counts`
- `GET /tenants/{tenantId}/audit/events?day=YYYY-MM-DD&limit=200&cursor=...&ruleId=...&action=...&key=...&signal=...`
- `POST /tenants/{tenantId}/audit/events`

Audit payload example:

```json
{
  "ruleId": "drop_key.http.request.header.authorization",
  "count": 3,
  "day": "2026-02-16"
}
```

Audit events payload example:

```json
{
  "events": [
    {
      "ruleId": "mask.email",
      "action": "mask",
      "key": "log.body",
      "signal": "logs",
      "count": 1,
      "timestamp": "2026-02-22T20:27:40.184830142Z"
    }
  ]
}
```

## Notes

- Update `collector/config/policy.yaml` to change redaction rules.
- `collector/config/collector.yaml` is the standalone local config.
- `collector/config/collector.compose.yaml` is the compose config with remote policy/audit against the local mock control plane.
- Set `rules[].id` in policy for stable audit keys (`drop.secrets`, `mask.email`, `tokenize.user`).
- Sample app emits logs, traces, and metrics with intentionally sensitive fields.
