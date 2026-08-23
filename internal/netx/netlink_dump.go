package netx

import (
	"errors"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

const (
	netlinkDumpAttempts   = 5
	netlinkDumpRetryDelay = 10 * time.Millisecond
)

func retryNetlinkDump[T any](fn func() (T, error)) (T, error) {
	var zero T
	var err error
	for attempt := 0; attempt < netlinkDumpAttempts; attempt++ {
		value, listErr := fn()
		if listErr == nil {
			return value, nil
		}
		err = listErr
		if !errors.Is(listErr, nl.ErrDumpInterrupted) {
			return zero, listErr
		}
		if attempt+1 < netlinkDumpAttempts {
			time.Sleep(time.Duration(attempt+1) * netlinkDumpRetryDelay)
		}
	}
	return zero, err
}

func listHostLinks() ([]netlink.Link, error) {
	return retryNetlinkDump(netlink.LinkList)
}

func listHandleLinks(h *netlink.Handle) ([]netlink.Link, error) {
	return retryNetlinkDump(h.LinkList)
}
