package engine

import (
	"context"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
)

type APIValidator struct {
	router routers.Router
}

func NewAPIValidator(specData []byte) (*APIValidator, error) {
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(specData)
	if err != nil {
		return nil, err
	}

	router, err := gorillamux.NewRouter(doc)
	if err != nil {
		return nil, err
	}

	return &APIValidator{router: router}, nil
}

func (v *APIValidator) ValidateRequest(req *http.Request) error {
	route, pathParams, err := v.router.FindRoute(req)
	if err != nil {
		return err
	}

	requestValidationInput := &openapi3filter.RequestValidationInput{
		Request:    req,
		PathParams: pathParams,
		Route:      route,
	}

	return openapi3filter.ValidateRequest(context.Background(), requestValidationInput)
}
