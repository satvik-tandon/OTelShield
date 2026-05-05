package redactprocessor

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/processor"
	"go.opentelemetry.io/collector/processor/processorhelper"
)

const typeStr = "redactprocessor"

// NewFactory creates the factory for the redactprocessor.
func NewFactory() processor.Factory {
	return processor.NewFactory(
		component.MustNewType(typeStr),
		createDefaultConfig,
		processor.WithLogs(createLogsProcessor, component.StabilityLevelBeta),
		processor.WithTraces(createTracesProcessor, component.StabilityLevelBeta),
		processor.WithMetrics(createMetricsProcessor, component.StabilityLevelBeta),
	)
}

func createDefaultConfig() component.Config {
	return &Config{
		PolicySource: PolicySource{Mode: "local"},
		Audit:        AuditSink{},
		HMACSecrets:  map[string]string{},
		Rules:        []Rule{},
	}
}

func createLogsProcessor(
	ctx context.Context,
	set processor.Settings,
	cfg component.Config,
	next consumer.Logs,
) (processor.Logs, error) {
	rp, err := newRedactProcessor(cfg, set.Logger)
	if err != nil {
		return nil, err
	}
	return processorhelper.NewLogs(
		ctx,
		set,
		cfg,
		next,
		rp.processLogs,
		processorhelper.WithStart(rp.start),
		processorhelper.WithShutdown(rp.shutdown),
	)
}

func createTracesProcessor(
	ctx context.Context,
	set processor.Settings,
	cfg component.Config,
	next consumer.Traces,
) (processor.Traces, error) {
	rp, err := newRedactProcessor(cfg, set.Logger)
	if err != nil {
		return nil, err
	}
	return processorhelper.NewTraces(
		ctx,
		set,
		cfg,
		next,
		rp.processTraces,
		processorhelper.WithStart(rp.start),
		processorhelper.WithShutdown(rp.shutdown),
	)
}

func createMetricsProcessor(
	ctx context.Context,
	set processor.Settings,
	cfg component.Config,
	next consumer.Metrics,
) (processor.Metrics, error) {
	rp, err := newRedactProcessor(cfg, set.Logger)
	if err != nil {
		return nil, err
	}
	return processorhelper.NewMetrics(
		ctx,
		set,
		cfg,
		next,
		rp.processMetrics,
		processorhelper.WithStart(rp.start),
		processorhelper.WithShutdown(rp.shutdown),
	)
}
