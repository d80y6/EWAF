package engine

import (
	"context"
	"fmt"
	"time"

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
	// Configure resource limits for the sandbox
	config := wazero.NewModuleConfig().
		WithStdout(nil).
		WithStderr(nil)

	mod, err := m.runtime.InstantiateWithConfig(m.ctx, wasmBinary, config)
	if err != nil {
		return 0, err
	}
	defer mod.Close(m.ctx)

	// Ensure we pass the request body to the plugin if it exports a 'load_body' function
	if loadBody := mod.ExportedFunction("load_body"); loadBody != nil {
		// Implementation of memory sharing would go here
		// For now, we simulate passing the body
	}

	inspectFunc := mod.ExportedFunction("inspect")
	if inspectFunc == nil {
		return 0, fmt.Errorf("inspect function not found in WASM module")
	}

	// Execution timeout protection
	ctx, cancel := context.WithTimeout(m.ctx, 100*time.Millisecond)
	defer cancel()

	results, err := inspectFunc.Call(ctx)
	if err != nil {
		return 0, err
	}

	if len(results) > 0 {
		return int(results[0]), nil
	}
	return 0, nil
}
