package engine

import (
	"github.com/graphql-go/graphql/language/ast"
	"github.com/graphql-go/graphql/language/parser"
	"github.com/graphql-go/graphql/language/source"
)

type GraphQLAnalyzer struct {
	MaxDepth      int
	MaxComplexity int
}

func (a *GraphQLAnalyzer) Analyze(query string) (int, int, error) {
	s := source.NewSource(&source.Source{
		Body: []byte(query),
		Name: "GraphQL request",
	})
	doc, err := parser.Parse(parser.ParseParams{Source: s})
	if err != nil {
		return 0, 0, err
	}

	depth := 0
	complexity := 0

	for _, def := range doc.Definitions {
		if op, ok := def.(*ast.OperationDefinition); ok {
			d, c := a.inspectSelectionSett(op.SelectionSet)
			if d > depth {
				depth = d
			}
			complexity += c
		}
	}

	return depth, complexity, nil
}

func (a *GraphQLAnalyzer) inspectSelectionSett(ss *ast.SelectionSet) (int, int) {
	if ss == nil {
		return 0, 0
	}

	maxDepth := 0
	totalComplexity := 0

	for _, selection := range ss.Selections {
		totalComplexity++
		if field, ok := selection.(*ast.Field); ok {
			d, c := a.inspectSelectionSett(field.SelectionSet)
			if d > maxDepth {
				maxDepth = d
			}
			totalComplexity += c
		}
	}

	return maxDepth + 1, totalComplexity
}
