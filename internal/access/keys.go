package access

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// argonish derives a verifier from a salted password.
//
// It is deliberately iterated rather than a single hash: a roster is a file
// that can be copied, and a single round of SHA-256 over a short course
// password is recovered by an attacker in seconds. This is not a substitute for
// a memory-hard function, and it is not protecting anything worth attacking,
// but it costs nothing and removes the version of this file that would be
// embarrassing to explain.
func argonish(seed []byte) []byte {
	const rounds = 64 * 1024
	h := sha256.Sum256(seed)
	for i := 0; i < rounds; i++ {
		h = sha256.Sum256(append(h[:], byte(i), byte(i>>8), byte(i>>16)))
	}
	return h[:]
}

// marshalED25519 encodes a private key in OpenSSH's PEM format.
//
// Go's standard library can parse this format but not write it, and the
// alternative -- shelling out to ssh-keygen -- would make the gateway depend on
// a binary that need not be installed anywhere it runs.
func marshalED25519(key ed25519.PrivateKey) (*pem.Block, error) {
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ed25519 key")
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, err
	}

	var check [4]byte
	if _, err := rand.Read(check[:]); err != nil {
		return nil, err
	}
	ci := uint32(check[0])<<24 | uint32(check[1])<<16 | uint32(check[2])<<8 | uint32(check[3])

	privBlob := ssh.Marshal(struct {
		Check1  uint32
		Check2  uint32
		Keytype string
		Pub     []byte
		Priv    []byte
		Comment string
	}{ci, ci, ssh.KeyAlgoED25519, pub, key, "twinet-gateway"})

	// The private section is padded to the cipher block size, which for an
	// unencrypted key is 8.
	for i := 0; len(privBlob)%8 != 0; i++ {
		privBlob = append(privBlob, byte(i+1))
	}

	blob := ssh.Marshal(struct {
		CipherName   string
		KdfName      string
		KdfOpts      string
		NumKeys      uint32
		PubKey       []byte
		PrivKeyBlock []byte
	}{"none", "none", "", 1, sshPub.Marshal(), privBlob})

	return &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: append([]byte("openssh-key-v1\x00"), blob...),
	}, nil
}
