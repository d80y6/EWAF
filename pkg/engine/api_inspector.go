package engine

import (
	"context"
	"strings"

	"github.com/sentinel-waf/sentinel-waf/pkg/model"
)

func (e *Engine) InspectAPI(ctx context.Context, req *model.RequestContext, policies []model.APISecurityPolicy) bool {
	for _, policy := range policies {
		if !strings.HasPrefix(req.URL, policy.PathPrefix) {
			continue
		}

		if policy.JWTVaildation {
			valid, err := e.ValidateJWT(req, policy)
			if !valid || err != nil {
				req.MatchedRules = append(req.MatchedRules, "API_JWT_INVALID")
				return true // block
			}
		}
	}
	return false
}
