package redactprocessor

import (
	"context"

	"go.opentelemetry.io/collector/pdata/ptrace"
)

func (rp *redactProcessor) processTraces(_ context.Context, td ptrace.Traces) (ptrace.Traces, error) {
	resources := td.ResourceSpans()
	for i := 0; i < resources.Len(); i++ {
		rs := resources.At(i)
		rp.policy.applyResourceAttributes(rs.Resource().Attributes())
		scopeSpans := rs.ScopeSpans()
		for j := 0; j < scopeSpans.Len(); j++ {
			spans := scopeSpans.At(j).Spans()
			for k := 0; k < spans.Len(); k++ {
				span := spans.At(k)
				rp.policy.applyAttributeRules(span.Attributes(), rp.policy.maskAttributeRules)
				events := span.Events()
				for e := 0; e < events.Len(); e++ {
					rp.policy.applyAttributeRules(events.At(e).Attributes(), rp.policy.maskAttributeRules)
				}
				links := span.Links()
				for l := 0; l < links.Len(); l++ {
					rp.policy.applyAttributeRules(links.At(l).Attributes(), rp.policy.maskAttributeRules)
				}
			}
		}
	}
	return td, nil
}
