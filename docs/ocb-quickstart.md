# OTelShield ocb quickstart (Ubuntu 20.04)

This is a copy/paste path to build the custom Collector with a local processor and validate it using `telemetrygen`.

## Prereqs

```bash
sudo apt update
sudo apt install -y git curl make unzip

sudo apt install -y docker.io docker-compose-plugin
sudo usermod -aG docker "$USER"
newgrp docker

sudo snap install go --classic
go version
```

## Build the Collector (local ocb)

```bash
cd /home/satvvik/OTelShield/collector
go install go.opentelemetry.io/collector/cmd/builder@v0.143.0
ocb --config builder-config.yaml
ls -la dist
```

## Run the Collector

```bash
./dist/otelshieldcol --config config/collector.yaml
```

## Generate test telemetry

```bash
export GOBIN=${GOBIN:-$(go env GOPATH)/bin}
go install github.com/open-telemetry/opentelemetry-collector-contrib/cmd/telemetrygen@latest

$GOBIN/telemetrygen traces --otlp-insecure --traces 3 --otlp-endpoint localhost:4317
```

You should see spans in the Collector stdout via the logging exporter.

## Optional: OpenTelemetry Demo (realistic traffic)

```bash
git clone https://github.com/open-telemetry/opentelemetry-demo.git
cd opentelemetry-demo
docker compose up --force-recreate --remove-orphans --detach
```
