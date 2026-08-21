package svc

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

func matrixBatchTopology(n int) *model.Topology {
	top := &model.Topology{Name: "matrix", Devices: map[string]*model.Device{}, ASes: map[int]*model.AS{}}
	for asn := 1; asn <= n; asn++ {
		device := &model.Device{
			ID: fmt.Sprintf("as%d/H", asn), Name: "H", ASN: asn, Kind: model.KindHost,
			Ifaces: []*model.Iface{{Name: "eth0", Addr4: fmt.Sprintf("10.%d.0.2/24", asn)}},
		}
		as := &model.AS{ASN: asn, Devices: []*model.Device{device}}
		top.ASes[asn] = as
		top.Devices[device.ID] = device
	}
	return top
}

func TestMatrixSourceBatchUsesAtMostTwoExecsPerSource(t *testing.T) {
	top := matrixBatchTopology(82)
	probeCalls := map[string]int{}
	pathCalls := map[string]int{}
	var callsMu sync.Mutex
	matrix := BuildMatrixWithSourceBatches(context.Background(), top,
		func(_ context.Context, source string, targets map[int]string) (map[int]BatchProbeResult, error) {
			callsMu.Lock()
			probeCalls[source]++
			callsMu.Unlock()
			out := map[int]BatchProbeResult{}
			for asn := range targets {
				out[asn] = BatchProbeResult{Reachable: true, RTTms: float64(asn)}
			}
			return out, nil
		},
		func(_ context.Context, source string, targets map[int]string) (map[int]BatchPathResult, error) {
			callsMu.Lock()
			pathCalls[source]++
			callsMu.Unlock()
			out := map[int]BatchPathResult{}
			for asn := range targets {
				out[asn] = BatchPathResult{Path: []int{asn}}
			}
			return out, nil
		}, 8)
	if got, want := matrix.Total, 82*81; got != want {
		t.Fatalf("matrix total = %d, want %d", got, want)
	}
	if matrix.Reachable != matrix.Total {
		t.Fatalf("batched matrix reachable = %d/%d", matrix.Reachable, matrix.Total)
	}
	for asn := 1; asn <= 82; asn++ {
		source := fmt.Sprintf("as%d/H", asn)
		callsMu.Lock()
		probes, paths := probeCalls[source], pathCalls[source]
		callsMu.Unlock()
		if probes != 1 || paths != 1 {
			t.Fatalf("%s used %d probe and %d path execs, want one of each",
				source, probes, paths)
		}
	}
}

func TestMatrixSourceBatchPreservesUnknownAndPolicyVerdicts(t *testing.T) {
	top := matrixBatchTopology(3)
	matrix := BuildMatrixWithSourceBatches(context.Background(), top,
		func(_ context.Context, source string, targets map[int]string) (map[int]BatchProbeResult, error) {
			out := map[int]BatchProbeResult{}
			for asn := range targets {
				if source == "as1/H" && asn == 2 {
					out[asn] = BatchProbeResult{Err: fmt.Errorf("source exec unavailable")}
					continue
				}
				out[asn] = BatchProbeResult{Reachable: true, RTTms: 2}
			}
			return out, nil
		},
		func(_ context.Context, _ string, targets map[int]string) (map[int]BatchPathResult, error) {
			out := map[int]BatchPathResult{}
			for asn := range targets {
				out[asn] = BatchPathResult{}
			}
			return out, nil
		}, 1)
	for _, cell := range matrix.Cells {
		if cell.From == 1 && cell.To == 2 {
			if cell.State != ReachUnknown || cell.Detail == "" {
				t.Fatalf("batch error became %#v, want explicit unknown", cell)
			}
			return
		}
	}
	t.Fatal("missing source/target cell")
}

func TestMatrixSourceBatchMatchesPerCellResults(t *testing.T) {
	top := matrixBatchTopology(4)
	legacy := BuildMatrixWithPaths(context.Background(), top,
		func(_ context.Context, _ string, target string) (bool, float64, error) {
			return true, float64(len(target)), nil
		},
		func(_ context.Context, _ string, to int) ([]int, error) {
			return []int{to}, nil
		}, 4)
	batched := BuildMatrixWithSourceBatches(context.Background(), top,
		func(_ context.Context, _ string, targets map[int]string) (map[int]BatchProbeResult, error) {
			out := map[int]BatchProbeResult{}
			for asn, target := range targets {
				out[asn] = BatchProbeResult{Reachable: true, RTTms: float64(len(target))}
			}
			return out, nil
		},
		func(_ context.Context, _ string, targets map[int]string) (map[int]BatchPathResult, error) {
			out := map[int]BatchPathResult{}
			for asn := range targets {
				out[asn] = BatchPathResult{Path: []int{asn}}
			}
			return out, nil
		}, 2)
	if len(legacy.Cells) != len(batched.Cells) {
		t.Fatalf("cell count differs: %d != %d", len(legacy.Cells), len(batched.Cells))
	}
	for index := range legacy.Cells {
		want, got := legacy.Cells[index], batched.Cells[index]
		if want.From != got.From || want.To != got.To || want.State != got.State || want.RTTms != got.RTTms {
			t.Fatalf("cell %d differs: legacy=%#v batch=%#v", index, want, got)
		}
	}
}
