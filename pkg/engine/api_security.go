package engine

import (
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sentinel-waf/sentinel-waf/pkg/model"
)

func (e *Engine) ValidateJWT(req *model.RequestContext, policy model.APISecurityPolicy) (bool, error) {
	authHeader := req.Headers.Get("Authorization")
	if authHeader == "" {
		return false, fmt.Errorf("missing authorization header")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return false, fmt.Errorf("invalid authorization header format")
	}

	tokenString := parts[1]
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(policy.JWTSecret), nil
	})

	if err != nil {
		return false, err
	}

	return token.Valid, nil
}
