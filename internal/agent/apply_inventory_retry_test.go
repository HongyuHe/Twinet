package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestCommitInventoryRepairsAndResnapshotsAMissingVNI(t *testing.T) {
	checks, repairs := 0, 0
	err := retryMissingDesiredVNI(context.Background(), 3, func() error {
		checks++
		if checks < 3 {
			return fmt.Errorf("inventory: %w", &desiredVNIAbsentError{VNI: 4720289})
		}
		return nil
	}, func() error {
		repairs++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checks != 3 || repairs != 2 {
		t.Fatalf("checks/repairs = %d/%d, want 3/2", checks, repairs)
	}
}

func TestCommitInventoryDoesNotRepairAContainerMismatch(t *testing.T) {
	repairs := 0
	want := errors.New("desired object is absent")
	err := retryMissingDesiredVNI(context.Background(), 3, func() error {
		return want
	}, func() error {
		repairs++
		return nil
	})
	if !errors.Is(err, want) || repairs != 0 {
		t.Fatalf("error/repairs = %v/%d, want original error and no overlay repair", err, repairs)
	}
}

func TestCommitInventoryBoundsMissingVNIRepair(t *testing.T) {
	checks, repairs := 0, 0
	err := retryMissingDesiredVNI(context.Background(), 3, func() error {
		checks++
		return &desiredVNIAbsentError{VNI: 7}
	}, func() error {
		repairs++
		return nil
	})
	var missing *desiredVNIAbsentError
	if !errors.As(err, &missing) || missing.VNI != 7 {
		t.Fatalf("error = %v, want missing VNI 7", err)
	}
	if checks != 3 || repairs != 2 {
		t.Fatalf("checks/repairs = %d/%d, want 3/2", checks, repairs)
	}
}

func TestCommitInventorySurfacesOverlayRepairFailure(t *testing.T) {
	err := retryMissingDesiredVNI(context.Background(), 3, func() error {
		return &desiredVNIAbsentError{VNI: 9}
	}, func() error {
		return errors.New("netlink unavailable")
	})
	if err == nil || !strings.Contains(err.Error(), "desired VNI 9 is absent") ||
		!strings.Contains(err.Error(), "netlink unavailable") {
		t.Fatalf("error = %v, want inventory and repair failures", err)
	}
}
