package main

import (
	"context"
	"fmt"
	stdlog "log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	logapi "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
	otelmetric "go.opentelemetry.io/otel/metric"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
)

const (
	defaultEndpoint = "http://otelshield:4318"
)

func main() {
	ctx := context.Background()
	serviceName := getenv("OTEL_SERVICE_NAME", "sampleapp")
	baseEndpoint := getenv("OTEL_EXPORTER_OTLP_ENDPOINT", defaultEndpoint)

	res, err := resource.New(
		ctx,
		resource.WithAttributes(
			attribute.String("service.name", serviceName),
			attribute.String("deployment.environment", "demo"),
		),
	)
	if err != nil {
		stdlog.Fatalf("failed to build resource: %v", err)
	}

	traceExporter, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpointURL(fmt.Sprintf("%s/v1/traces", baseEndpoint)),
		otlptracehttp.WithInsecure(),
	)
	if err != nil {
		stdlog.Fatalf("failed to create trace exporter: %v", err)
	}
	tracerProvider := trace.NewTracerProvider(
		trace.WithBatcher(traceExporter),
		trace.WithResource(res),
	)
	otel.SetTracerProvider(tracerProvider)

	metricExporter, err := otlpmetrichttp.New(ctx,
		otlpmetrichttp.WithEndpointURL(fmt.Sprintf("%s/v1/metrics", baseEndpoint)),
		otlpmetrichttp.WithInsecure(),
	)
	if err != nil {
		stdlog.Fatalf("failed to create metric exporter: %v", err)
	}
	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExporter)),
		sdkmetric.WithResource(res),
	)
	otel.SetMeterProvider(meterProvider)

	logExporter, err := otlploghttp.New(ctx,
		otlploghttp.WithEndpointURL(fmt.Sprintf("%s/v1/logs", baseEndpoint)),
		otlploghttp.WithInsecure(),
	)
	if err != nil {
		stdlog.Fatalf("failed to create log exporter: %v", err)
	}
	loggerProvider := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(logExporter)),
		sdklog.WithResource(res),
	)
	global.SetLoggerProvider(loggerProvider)

	meter := otel.Meter("sampleapp")
	requestCounter, _ := meter.Int64Counter("checkout.requests")
	latencyHistogram, _ := meter.Float64Histogram("checkout.latency_ms")
	tracer := otel.Tracer("sampleapp")

	mux := http.NewServeMux()
	mux.Handle("/checkout", otelhttp.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ctx, span := tracer.Start(r.Context(), "checkout")
		defer span.End()

		userID := "user-123"
		email := "jane.doe@example.com"

		span.SetAttributes(
			attribute.String("user.id", userID),
			attribute.String("enduser.id", userID),
			attribute.String("http.request.header.authorization", "Bearer secret-token"),
			attribute.String("http.request.header.cookie", "session=secret"),
			attribute.String("db.statement", fmt.Sprintf("SELECT * FROM users WHERE email='%s'", email)),
		)

		emitLog(ctx, "checkout.failed", fmt.Sprintf("checkout failed for %s", email), []logapi.KeyValue{
			logapi.String("exception.message", fmt.Sprintf("payment failed for %s", email)),
			logapi.String("user.id", userID),
			logapi.String("enduser.id", userID),
			logapi.String("http.target", "/checkout?email="+email),
		})

		requestCounter.Add(ctx, 1, otelmetric.WithAttributes(attribute.String("user.id", userID)))
		latencyHistogram.Record(ctx, float64(time.Since(start).Milliseconds()), otelmetric.WithAttributes(attribute.String("user.id", userID)))

		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("checkout failed"))
	}), "Checkout"))

	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	server := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		stdlog.Printf("sample-app listening on %s", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			stdlog.Fatalf("server error: %v", err)
		}
	}()

	waitForShutdown(ctx, server, tracerProvider, meterProvider, loggerProvider)
}

func emitLog(ctx context.Context, eventName, body string, attrs []logapi.KeyValue) {
	logger := global.Logger("sampleapp")
	var record logapi.Record
	record.SetEventName(eventName)
	record.SetTimestamp(time.Now())
	record.SetSeverity(logapi.SeverityError)
	record.SetBody(logapi.StringValue(body))
	record.AddAttributes(attrs...)
	logger.Emit(ctx, record)
}

func waitForShutdown(ctx context.Context, server *http.Server, tracerProvider *trace.TracerProvider, meterProvider *sdkmetric.MeterProvider, loggerProvider *sdklog.LoggerProvider) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	shutdownCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	_ = server.Shutdown(shutdownCtx)
	_ = tracerProvider.Shutdown(shutdownCtx)
	_ = meterProvider.Shutdown(shutdownCtx)
	_ = loggerProvider.Shutdown(shutdownCtx)
}

func getenv(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}
