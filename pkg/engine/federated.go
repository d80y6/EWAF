package engine

type FederatedNode struct {
	ID string
	ModelWeights []float64
}

func (n *FederatedNode) SyncWeights(globalWeights []float64) {
	// Sync local behavioral weights with global model
	for i := range n.ModelWeights {
		n.ModelWeights[i] = (n.ModelWeights[i] + globalWeights[i]) / 2
	}
}
