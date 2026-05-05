package redactprocessor

import (
	"context"

	"go.opentelemetry.io/collector/pdata/pmetric"
)

func (rp *redactProcessor) processMetrics(_ context.Context, md pmetric.Metrics) (pmetric.Metrics, error) {
	policy := rp.activePolicy()
	if policy == nil {
		return md, nil
	}
	ruleHits := map[string]int64{}
	recorder := rp.auditRecorder("metrics")

	resources := md.ResourceMetrics()
	for i := 0; i < resources.Len(); i++ {
		rm := resources.At(i)
		policy.applyResourceAttributes(rm.Resource().Attributes(), ruleHits, recorder, "metrics")
		scopeMetrics := rm.ScopeMetrics()
		for j := 0; j < scopeMetrics.Len(); j++ {
			metrics := scopeMetrics.At(j).Metrics()
			for k := 0; k < metrics.Len(); k++ {
				metric := metrics.At(k)
				switch metric.Type() {
				case pmetric.MetricTypeGauge:
					applyNumberDataPoints(metric.Gauge().DataPoints(), policy, ruleHits, recorder)
				case pmetric.MetricTypeSum:
					applyNumberDataPoints(metric.Sum().DataPoints(), policy, ruleHits, recorder)
				case pmetric.MetricTypeHistogram:
					applyHistogramDataPoints(metric.Histogram().DataPoints(), policy, ruleHits, recorder)
				case pmetric.MetricTypeExponentialHistogram:
					applyExponentialHistogramDataPoints(metric.ExponentialHistogram().DataPoints(), policy, ruleHits, recorder)
				case pmetric.MetricTypeSummary:
					applySummaryDataPoints(metric.Summary().DataPoints(), policy, ruleHits, recorder)
				}
			}
		}
	}
	rp.addAuditHits(ruleHits)
	return md, nil
}

func applyNumberDataPoints(points pmetric.NumberDataPointSlice, policy *compiledPolicy, ruleHits map[string]int64, recorder auditRecorder) {
	for i := 0; i < points.Len(); i++ {
		policy.applyAttributeRules(points.At(i).Attributes(), policy.maskAttributeRules, ruleHits, recorder, "metrics")
	}
}

func applyHistogramDataPoints(points pmetric.HistogramDataPointSlice, policy *compiledPolicy, ruleHits map[string]int64, recorder auditRecorder) {
	for i := 0; i < points.Len(); i++ {
		policy.applyAttributeRules(points.At(i).Attributes(), policy.maskAttributeRules, ruleHits, recorder, "metrics")
	}
}

func applyExponentialHistogramDataPoints(points pmetric.ExponentialHistogramDataPointSlice, policy *compiledPolicy, ruleHits map[string]int64, recorder auditRecorder) {
	for i := 0; i < points.Len(); i++ {
		policy.applyAttributeRules(points.At(i).Attributes(), policy.maskAttributeRules, ruleHits, recorder, "metrics")
	}
}

func applySummaryDataPoints(points pmetric.SummaryDataPointSlice, policy *compiledPolicy, ruleHits map[string]int64, recorder auditRecorder) {
	for i := 0; i < points.Len(); i++ {
		policy.applyAttributeRules(points.At(i).Attributes(), policy.maskAttributeRules, ruleHits, recorder, "metrics")
	}
}
