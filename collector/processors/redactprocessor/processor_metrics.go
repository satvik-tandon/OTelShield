package redactprocessor

import (
	"context"

	"go.opentelemetry.io/collector/pdata/pmetric"
)

func (rp *redactProcessor) processMetrics(_ context.Context, md pmetric.Metrics) (pmetric.Metrics, error) {
	resources := md.ResourceMetrics()
	for i := 0; i < resources.Len(); i++ {
		rm := resources.At(i)
		rp.policy.applyResourceAttributes(rm.Resource().Attributes())
		scopeMetrics := rm.ScopeMetrics()
		for j := 0; j < scopeMetrics.Len(); j++ {
			metrics := scopeMetrics.At(j).Metrics()
			for k := 0; k < metrics.Len(); k++ {
				metric := metrics.At(k)
				switch metric.Type() {
				case pmetric.MetricTypeGauge:
					applyNumberDataPoints(metric.Gauge().DataPoints(), rp)
				case pmetric.MetricTypeSum:
					applyNumberDataPoints(metric.Sum().DataPoints(), rp)
				case pmetric.MetricTypeHistogram:
					applyHistogramDataPoints(metric.Histogram().DataPoints(), rp)
				case pmetric.MetricTypeExponentialHistogram:
					applyExponentialHistogramDataPoints(metric.ExponentialHistogram().DataPoints(), rp)
				case pmetric.MetricTypeSummary:
					applySummaryDataPoints(metric.Summary().DataPoints(), rp)
				}
			}
		}
	}
	return md, nil
}

func applyNumberDataPoints(points pmetric.NumberDataPointSlice, rp *redactProcessor) {
	for i := 0; i < points.Len(); i++ {
		rp.policy.applyAttributeRules(points.At(i).Attributes(), rp.policy.maskAttributeRules)
	}
}

func applyHistogramDataPoints(points pmetric.HistogramDataPointSlice, rp *redactProcessor) {
	for i := 0; i < points.Len(); i++ {
		rp.policy.applyAttributeRules(points.At(i).Attributes(), rp.policy.maskAttributeRules)
	}
}

func applyExponentialHistogramDataPoints(points pmetric.ExponentialHistogramDataPointSlice, rp *redactProcessor) {
	for i := 0; i < points.Len(); i++ {
		rp.policy.applyAttributeRules(points.At(i).Attributes(), rp.policy.maskAttributeRules)
	}
}

func applySummaryDataPoints(points pmetric.SummaryDataPointSlice, rp *redactProcessor) {
	for i := 0; i < points.Len(); i++ {
		rp.policy.applyAttributeRules(points.At(i).Attributes(), rp.policy.maskAttributeRules)
	}
}
