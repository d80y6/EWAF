package engine

import (
	"github.com/sentinel-waf/sentinel-waf/pkg/model"
)

type StatsCollector interface {
	RecordRequest(req *model.RequestContext, blocked bool, anomaly bool, apiViolation bool)
}
