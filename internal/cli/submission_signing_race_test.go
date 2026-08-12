package cli

import (
	"crypto/ed25519"
	"sync"
	"testing"
)

// The signing key's load-or-create is reached by eight collectors at once, and
// by more than one machine at a time. Done unlocked it is a race: two callers
// each mint a different keypair and overwrite each other's halves, leaving a
// public key that does not verify the private key the archives were signed
// with. Nothing notices until grading, by which time the archives are collected
// and the cause is gone.
//
// So every caller must come away with the same keypair, and the stored public
// half must correspond to it. This drives many goroutines through the
// load-or-create at once and requires exactly that. Run it with -race.
func TestSigningKeyLoadOrCreateYieldsOneKeypairUnderConcurrency(t *testing.T) {
	t.Setenv("TWINET_PKI", t.TempDir())

	const workers = 32
	keys := make([]ed25519.PrivateKey, workers)
	errs := make([]error, workers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // release all workers as close together as possible
			keys[i], errs[i] = submissionKey()
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("worker %d could not load-or-create the signing key: %v", i, err)
		}
	}
	for i := 1; i < workers; i++ {
		if !keys[i].Equal(keys[0]) {
			t.Fatalf("worker %d came away with a different private key than worker 0.\n"+
				"Two concurrent first-time uses each generated a keypair and overwrote "+
				"each other's halves, so an archive signed by one verifies against neither.", i)
		}
	}

	// The public half on disk must be the one that verifies what the workers
	// signed with, or a save collected now produces archives that fail at
	// grading time for no reconstructable reason.
	pub, err := submissionPublicKey()
	if err != nil {
		t.Fatalf("the stored public half could not be read back: %v", err)
	}
	if !keys[0].Public().(ed25519.PublicKey).Equal(pub) {
		t.Fatal("the stored public key does not correspond to the private key every worker " +
			"loaded, so archives signed now would verify as untrusted")
	}

	// End to end: a bundle signed with the loaded private key verifies under
	// the stored public key.
	b := Bundle{Lab: "cos461", AS: 3, Group: "group3", Files: map[string]string{"ATL.conf": "aaaa"}}
	if !verifyBundle(b, signBundle(b, keys[0]), pub) {
		t.Fatal("a bundle signed with the load-or-create key does not verify under the stored " +
			"public key, so the two halves are not a pair")
	}
}
