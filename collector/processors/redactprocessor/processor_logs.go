package redactprocessor

import (
	"context"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
)

func (rp *redactProcessor) processLogs(_ context.Context, ld plog.Logs) (plog.Logs, error) {
	policy := rp.activePolicy()
	if policy == nil {
		return ld, nil
	}
	ruleHits := map[string]int64{}
	recorder := rp.auditRecorder("logs")

	resources := ld.ResourceLogs()
	for i := 0; i < resources.Len(); i++ {
		rl := resources.At(i)
		policy.applyResourceAttributes(rl.Resource().Attributes(), ruleHits, recorder, "logs")
		scopeLogs := rl.ScopeLogs()
		for j := 0; j < scopeLogs.Len(); j++ {
			logRecords := scopeLogs.At(j).LogRecords()
			for k := 0; k < logRecords.Len(); k++ {
				lr := logRecords.At(k)
				policy.applyAttributeRules(lr.Attributes(), policy.maskAttributeRules, ruleHits, recorder, "logs")
				if lr.Body().Type() == pcommon.ValueTypeStr {
					lr.Body().SetStr(applyMaskRules(lr.Body().Str(), policy.maskLogBodyRules, ruleHits, recorder, "log.body", "logs"))
				}
			}
		}
	}
	rp.addAuditHits(ruleHits)
	return ld, nil
}
