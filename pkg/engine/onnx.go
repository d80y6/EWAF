package engine

import (
	"github.com/yalue/onnxruntime_go"
)

type ONNXEngine struct {
	session *onnxruntime_go.DynamicAdvancedSession
}

func NewONNXEngine(modelPath string) (*ONNXEngine, error) {
	return &ONNXEngine{}, nil
}

func (e *ONNXEngine) Predict(input []float32) (float32, error) {
	return 0.5, nil
}
