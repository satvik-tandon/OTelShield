package redactprocessor

import (
	"context"

	"go.opentelemetry.io/collector/pdata/ptrace"
)

func (rp *redactProcessor) processTraces(_ context.Context, td ptrace.Traces) (ptrace.Traces, error) {
	policy := rp.activePolicy()
	if policy == nil {
		return td, nil
	}
	ruleHits := map[string]int64{}

	resources := td.ResourceSpans()
	for i := 0; i < resources.Len(); i++ {
		rs := resources.At(i)
		policy.applyResourceAttributes(rs.Resource().Attributes(), ruleHits)
		scopeSpans := rs.ScopeSpans()
		for j := 0; j < scopeSpans.Len(); j++ {
			spans := scopeSpans.At(j).Spans()
			for k := 0; k < spans.Len(); k++ {
				span := spans.At(k)
				policy.applyAttributeRules(span.Attributes(), policy.maskAttributeRules, ruleHits)
				events := span.Events()
				for e := 0; e < events.Len(); e++ {
					policy.applyAttributeRules(events.At(e).Attributes(), policy.maskAttributeRules, ruleHits)
				}
				links := span.Links()
				for l := 0; l < links.Len(); l++ {
					policy.applyAttributeRules(links.At(l).Attributes(), policy.maskAttributeRules, ruleHits)
				}
			}
		}
	}
	rp.addAuditHits(ruleHits)
	return td, nil
}
