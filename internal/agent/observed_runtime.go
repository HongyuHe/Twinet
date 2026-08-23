package agent

import (
	"context"
	"time"

	"github.com/HongyuHe/twinet/internal/limiter"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// observedRuntime keeps runtime accounting at the only process that owns a
// node-wide runtime client. It deliberately does not change the Runtime
// contract, so deploy, durability, and repair all gain the same accounting.
type observedRuntime struct {
	runtime rt.Runtime
	metrics *agentMetrics
	limiter *limiter.Limiter
}

func observeRuntimeCall[T any](m *agentMetrics, method string, fn func() (T, error)) (T, error) {
	start := time.Now()
	value, err := fn()
	m.observeRuntime(method, time.Since(start), err)
	return value, err
}

func observeRuntimeError(m *agentMetrics, method string, fn func() error) error {
	start := time.Now()
	err := fn()
	m.observeRuntime(method, time.Since(start), err)
	return err
}

func (r *observedRuntime) Name() string { return r.runtime.Name() }

// RuntimeEndpoint preserves the selected backend socket through the metrics
// wrapper. Status must report the actual socket, not lose it merely because
// runtime calls are being observed.
func (r *observedRuntime) RuntimeEndpoint() string { return rt.Endpoint(r.runtime) }

func (r *observedRuntime) SetRuntimeEndpoint(endpoint string) error {
	return rt.ConfigureEndpoint(r.runtime, endpoint)
}

func (r *observedRuntime) Ping(ctx context.Context) (string, error) {
	return observeRuntimeCall(r.metrics, "ping", func() (string, error) { return r.runtime.Ping(ctx) })
}

func (r *observedRuntime) PullImage(ctx context.Context, ref string, policy rt.PullPolicy) error {
	return observeRuntimeError(r.metrics, "pull", func() error { return r.runtime.PullImage(ctx, ref, policy) })
}

func (r *observedRuntime) ImageExists(ctx context.Context, ref string) (bool, error) {
	return observeRuntimeCall(r.metrics, "inspect", func() (bool, error) { return r.runtime.ImageExists(ctx, ref) })
}

func (r *observedRuntime) Create(ctx context.Context, spec *rt.Spec) (string, error) {
	var id string
	err := r.limiter.Run(ctx, []limiter.Kind{limiter.ContainerCreate}, func() error {
		var createErr error
		id, createErr = observeRuntimeCall(r.metrics, "create",
			func() (string, error) { return r.runtime.Create(ctx, spec) })
		return createErr
	})
	return id, err
}

func (r *observedRuntime) Start(ctx context.Context, name string) error {
	return r.limiter.Run(ctx, []limiter.Kind{limiter.ContainerStart}, func() error {
		return observeRuntimeError(r.metrics, "start", func() error { return r.runtime.Start(ctx, name) })
	})
}

func (r *observedRuntime) Stop(ctx context.Context, name string, timeout time.Duration) error {
	return observeRuntimeError(r.metrics, "stop", func() error { return r.runtime.Stop(ctx, name, timeout) })
}

func (r *observedRuntime) Pause(ctx context.Context, name string) error {
	return observeRuntimeError(r.metrics, "pause", func() error { return r.runtime.Pause(ctx, name) })
}

func (r *observedRuntime) Unpause(ctx context.Context, name string) error {
	return observeRuntimeError(r.metrics, "unpause", func() error { return r.runtime.Unpause(ctx, name) })
}

func (r *observedRuntime) ImageDigest(ctx context.Context, ref string) (string, error) {
	return observeRuntimeCall(r.metrics, "inspect", func() (string, error) { return r.runtime.ImageDigest(ctx, ref) })
}

func (r *observedRuntime) Remove(ctx context.Context, name string, force bool) error {
	return observeRuntimeError(r.metrics, "remove", func() error { return r.runtime.Remove(ctx, name, force) })
}

func (r *observedRuntime) Inspect(ctx context.Context, name string) (rt.Container, error) {
	return observeRuntimeCall(r.metrics, "inspect", func() (rt.Container, error) { return r.runtime.Inspect(ctx, name) })
}

func (r *observedRuntime) List(ctx context.Context, filter rt.Filter) ([]rt.Container, error) {
	return observeRuntimeCall(r.metrics, "list", func() ([]rt.Container, error) { return r.runtime.List(ctx, filter) })
}

func (r *observedRuntime) NSPath(ctx context.Context, name string) (string, error) {
	return observeRuntimeCall(r.metrics, "nspath", func() (string, error) { return r.runtime.NSPath(ctx, name) })
}

func (r *observedRuntime) Exec(ctx context.Context, name string, cmd rt.ExecCmd) (rt.ExecResult, error) {
	return observeRuntimeCall(r.metrics, "exec", func() (rt.ExecResult, error) { return r.runtime.Exec(ctx, name, cmd) })
}

func (r *observedRuntime) CopyTo(ctx context.Context, name, path string, mode int64, content []byte) error {
	return observeRuntimeError(r.metrics, "copy_to", func() error {
		return r.runtime.CopyTo(ctx, name, path, mode, content)
	})
}

func (r *observedRuntime) CopyFrom(ctx context.Context, name, path string) ([]byte, error) {
	return observeRuntimeCall(r.metrics, "copy_from", func() ([]byte, error) {
		return r.runtime.CopyFrom(ctx, name, path)
	})
}

func (r *observedRuntime) Close() error {
	return observeRuntimeError(r.metrics, "other", r.runtime.Close)
}

var _ rt.Runtime = (*observedRuntime)(nil)
var _ rt.EndpointRuntime = (*observedRuntime)(nil)
