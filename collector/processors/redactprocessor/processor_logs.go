package redactprocessor

import (
	"context"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
)

func (rp *redactProcessor) processLogs(_ context.Context, ld plog.Logs) (plog.Logs, error) {
	resources := ld.ResourceLogs()
	for i := 0; i < resources.Len(); i++ {
		rl := resources.At(i)
		rp.policy.applyResourceAttributes(rl.Resource().Attributes())
		scopeLogs := rl.ScopeLogs()
		for j := 0; j < scopeLogs.Len(); j++ {
			logRecords := scopeLogs.At(j).LogRecords()
			for k := 0; k < logRecords.Len(); k++ {
				lr := logRecords.At(k)
				rp.policy.applyAttributeRules(lr.Attributes(), rp.policy.maskAttributeRules)
				if lr.Body().Type() == pcommon.ValueTypeStr {
					lr.Body().SetStr(applyMaskRules(lr.Body().Str(), rp.policy.maskLogBodyRules))
				}
			}
		}
	}
	return ld, nil
}
