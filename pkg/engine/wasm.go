package engine

import (
	"context"
	"fmt"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

type WASMManager struct {
	runtime wazero.Runtime
	ctx     context.Context
}

func NewWASMManager(ctx context.Context) *WASMManager {
	r := wazero.NewRuntime(ctx)
	wasi_snapshot_preview1.MustInstantiate(ctx, r)
	return &WASMManager{
		runtime: r,
		ctx:     ctx,
	}
}

func (m *WASMManager) RunPlugin(wasmBinary []byte, requestBody string) (int, error) {
	mod, err := m.runtime.Instantiate(m.ctx, wasmBinary)
	if err != nil {
		return 0, err
	}
	defer mod.Close(m.ctx)

	inspectFunc := mod.ExportedFunction("inspect")
	if inspectFunc == nil {
		return 0, fmt.Errorf("inspect function not found in WASM module")
	}

	results, err := inspectFunc.Call(m.ctx)
	if err != nil {
		return 0, err
	}

	if len(results) > 0 {
		return int(results[0]), nil
	}
	return 0, nil
}
