FROM golang:1.24 AS build
WORKDIR /src
ENV PATH="/go/bin:${PATH}"
COPY builder-config.yaml ./builder-config.yaml
COPY processors ./processors
RUN go install go.opentelemetry.io/collector/cmd/builder@v0.143.0
RUN ocb --config builder-config.yaml

FROM gcr.io/distroless/base-debian12
WORKDIR /
COPY --from=build /src/dist/otelshieldcol /otelshieldcol
COPY config/collector.yaml /etc/otelcol/config.yaml
COPY config/policy.yaml /etc/otelcol/policy.yaml
EXPOSE 4317 4318 13133 9464
ENTRYPOINT ["/otelshieldcol", "--config=/etc/otelcol/config.yaml"]
