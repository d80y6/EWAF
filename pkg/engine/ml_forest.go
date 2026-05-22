package engine

import (
	"math"
)

type IsolationForest struct {
	Trees []*Tree
}

type Tree struct {
	Left  *Tree
	Right *Tree
	SplitAttr  int
	SplitValue float64
	Size       int
}

func (f *IsolationForest) Score(x []float64) float64 {
	if len(f.Trees) == 0 {
		return 0
	}
	var sumPathLength float64
	for _, tree := range f.Trees {
		sumPathLength += f.pathLength(x, tree, 0)
	}
	avgPathLength := sumPathLength / float64(len(f.Trees))

	return math.Pow(2, -avgPathLength/f.c(len(f.Trees)))
}

func (f *IsolationForest) pathLength(x []float64, tree *Tree, currentPathLength int) float64 {
	if tree.Left == nil && tree.Right == nil {
		return float64(currentPathLength) + f.c(tree.Size)
	}

	if x[tree.SplitAttr] < tree.SplitValue {
		return f.pathLength(x, tree.Left, currentPathLength+1)
	}
	return f.pathLength(x, tree.Right, currentPathLength+1)
}

func (f *IsolationForest) c(n int) float64 {
	if n <= 1 {
		return 0
	}
	if n == 2 {
		return 1
	}
	return 2.0*(math.Log(float64(n-1))+0.5772156649) - (2.0 * float64(n-1) / float64(n))
}
