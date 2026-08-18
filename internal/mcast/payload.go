// Package mcast is the payload one multicast measurement sends, shared by the
// grader that draws it and the probe that stamps it.
//
// It exists so the two cannot drift. The bytes were written out with a format
// string in the probe and looked for with a second copy of that string in the
// check; a change to either would have been silently answered by every host
// reporting that nothing arrived, which reads exactly like a submission whose
// tree does not work.
package mcast

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Stamp is the payload of packet i in a run drawn with this tag.
//
// The tag is not a secret and cannot be one: in these exercises the student
// owns the sending host, so anything the probe puts on the wire can be read off
// it. What the tag buys is that a packet from *this* run can be told from
// whatever else is on the group -- including a sender the submission left
// running, which is how "something arrived" used to be satisfied without a tree.
func Stamp(tag string, i int) string {
	if tag == "" {
		return fmt.Sprintf("twinet-mcast %d", i)
	}
	return fmt.Sprintf("twinet-mcast %s %d", tag, i)
}

// Digest names a payload without reproducing it, so that what a host reports
// seeing can be matched against what was sent without the report itself
// becoming a copy of the tag.
func Digest(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// Digests are the names of every payload one run of n packets sends.
func Digests(tag string, n int) map[string]bool {
	out := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		out[Digest([]byte(Stamp(tag, i)))] = true
	}
	return out
}
