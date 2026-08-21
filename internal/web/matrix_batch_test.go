package web

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

func webBatchTopology() *model.Topology {
	top := &model.Topology{Name: "web", Devices: map[string]*model.Device{}, ASes: map[int]*model.AS{}}
	for asn := 1; asn <= 3; asn++ {
		device := &model.Device{
			ID: fmt.Sprintf("as%d/H", asn), Name: "H", ASN: asn, Kind: model.KindHost,
			Ifaces: []*model.Iface{{Name: "eth0", Addr4: fmt.Sprintf("10.%d.0.2/24", asn)}},
		}
		top.Devices[device.ID] = device
		top.ASes[asn] = &model.AS{ASN: asn, Devices: []*model.Device{device}}
	}
	return top
}

func TestWebMatrixUsesTwoSourceSideExecsPerAS(t *testing.T) {
	top := webBatchTopology()
	var mu sync.Mutex
	calls := map[string]int{}
	exec := func(_ context.Context, device string, command []string) (string, int, error) {
		mu.Lock()
		calls[device]++
		mu.Unlock()
		from, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(device, "as"), "/H"))
		script := command[len(command)-1]
		var out strings.Builder
		for to := 1; to <= 3; to++ {
			if to == from {
				continue
			}
			if strings.Contains(script, "__TWINET_PING__") {
				fmt.Fprintf(&out, "__TWINET_PING__%d\t0\t1.5\n", to)
				continue
			}
			fmt.Fprintf(&out, "__TWINET_PATH_BEGIN__%d\n", to)
			fmt.Fprintf(&out, "__TWINET_PATH_END__%d\t0\n", to)
		}
		return out.String(), 0, nil
	}
	server, err := New(top, exec)
	if err != nil {
		t.Fatal(err)
	}
	server.takeMatrix()
	matrix := server.cachedMatrix()
	if matrix == nil || matrix.Total != 6 || matrix.Reachable != 6 {
		t.Fatalf("batched web matrix = %#v", matrix)
	}
	for asn := 1; asn <= 3; asn++ {
		device := fmt.Sprintf("as%d/H", asn)
		mu.Lock()
		count := calls[device]
		mu.Unlock()
		if count != 2 {
			t.Fatalf("%s used %d container execs, want two", device, count)
		}
	}
	server.InvalidateMatrix()
	server.mu.Lock()
	invalidated := server.matrixAt.IsZero()
	server.mu.Unlock()
	if !invalidated {
		t.Fatal("runtime event invalidation left the matrix cache fresh")
	}
	if events := server.Collector.Events(); len(events) != 1 ||
		events[0].Service != "builtin.matrix" || events[0].Result != "success" {
		t.Fatalf("matrix batch did not publish a bounded collector event: %#v", events)
	}
}
