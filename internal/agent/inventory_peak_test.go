package agent

import "testing"

func TestInventoryPeakRetainsConvergenceHighWaterMark(t *testing.T) {
	observer := newHostInventoryObserver()
	firstCPU, firstMemory := 1.0, int64(100)
	first := observer.recordPeak(ResourceInventory{
		CPUs: &firstCPU, MemoryBytes: &firstMemory,
	})
	secondCPU, secondMemory := 0.5, int64(200)
	second := observer.recordPeak(ResourceInventory{
		CPUs: &secondCPU, MemoryBytes: &secondMemory,
	})
	if first.CPUs == nil || *first.CPUs != 1 {
		t.Fatalf("first peak = %+v", first)
	}
	if second.CPUs == nil || *second.CPUs != 1 || second.MemoryBytes == nil || *second.MemoryBytes != 200 {
		t.Fatalf("peak did not retain per-dimension maxima: %+v", second)
	}
}
