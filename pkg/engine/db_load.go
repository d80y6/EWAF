package engine

import (
	"github.com/sentinel-waf/sentinel-waf/pkg/model"
)

func (e *Engine) LoadDBRules(dbRules []model.Rule) error {
	var engineRules []model.Rule
	for _, dr := range dbRules {
		engineRules = append(engineRules, model.Rule{
			RuleID: dr.RuleID,
			Name: dr.Name,
			Action: dr.Action,
			Score: dr.Score,
			Conditions: dr.Conditions,
		})
	}
	return e.LoadRules(engineRules)
}
