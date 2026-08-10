package access

import (
	"encoding/base64"
	"strings"
	"testing"
)

// The roster is a file that can be copied. Storing what a student types would
// mean a leaked roster hands an attacker working credentials for a class.
func TestThePasswordItselfIsNeverStored(t *testing.T) {
	g := &Group{AS: 3}
	const pass = "correct horse battery staple"
	if err := g.SetPassword(pass); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(g.PasswordHash, pass) || strings.Contains(g.Salt, pass) {
		t.Fatal("the password appears in the stored record")
	}
	raw, err := base64.StdEncoding.DecodeString(g.PasswordHash)
	if err != nil {
		t.Fatalf("the stored verifier is not decodable: %v", err)
	}
	if strings.Contains(string(raw), pass) {
		t.Fatal("the password appears in the decoded verifier")
	}

	// The verifier must actually verify.
	if got := hashPassword(pass, g.Salt); base64.StdEncoding.EncodeToString(got) != g.PasswordHash {
		t.Error("the stored verifier does not match the password it was made from")
	}
	if got := hashPassword("wrong", g.Salt); base64.StdEncoding.EncodeToString(got) == g.PasswordHash {
		t.Error("a different password produces the same verifier")
	}
}

// Two groups with the same password must not have the same verifier, or one
// leaked verifier identifies every group sharing it.
func TestTwoGroupsWithOnePasswordDifferAnyway(t *testing.T) {
	a, b := &Group{AS: 3}, &Group{AS: 4}
	if err := a.SetPassword("same"); err != nil {
		t.Fatal(err)
	}
	if err := b.SetPassword("same"); err != nil {
		t.Fatal(err)
	}
	if a.Salt == b.Salt {
		t.Error("two groups were given the same salt")
	}
	if a.PasswordHash == b.PasswordHash {
		t.Error("two groups with one password have the same verifier")
	}
}

func TestGeneratedPasswordsAreNotGuessable(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		p, err := GeneratePassword()
		if err != nil {
			t.Fatal(err)
		}
		if len(p) < 12 {
			t.Fatalf("generated password %q is too short to be worth generating", p)
		}
		if seen[p] {
			t.Fatal("a generated password repeated within 200 draws")
		}
		seen[p] = true
	}
}

// A student names a device; the gateway looks it up within their own AS. That
// is the authorisation boundary, and it is a lookup rather than a check so that
// another group's router cannot be named at all.
func TestADeviceNameResolvesOnlyWithinTheSessionsOwnAS(t *testing.T) {
	top := twoASTopology()
	s := &Server{cfg: Config{Topology: top}}

	if got, err := s.resolve(Session{AS: 3}, "MSP"); err != nil || got != "as3/MSP" {
		t.Errorf("a student could not reach their own router: %q %v", got, err)
	}
	// Case should not matter to a person typing it.
	if got, err := s.resolve(Session{AS: 3}, "msp"); err != nil || got != "as3/MSP" {
		t.Errorf("device names are case-sensitive to a student: %q %v", got, err)
	}
	// The other group's router exists, and must still be unreachable.
	if _, err := s.resolve(Session{AS: 3}, "NYC"); err == nil {
		t.Error("a student reached a device belonging to another AS")
	}
	if _, err := s.resolve(Session{AS: 3}, "as4/NYC"); err == nil {
		t.Error("a fully-qualified name let a student escape their own AS")
	}
	// A session bound to no AS must reach nothing at all.
	if _, err := s.resolve(Session{}, "MSP"); err == nil {
		t.Error("an unbound session resolved a device")
	}
}

// The interactive menu lists the session's own devices, so it cannot become a
// directory of the whole class.
func TestTheDeviceListIsScopedToTheSession(t *testing.T) {
	top := twoASTopology()
	s := &Server{cfg: Config{Topology: top}}
	for _, d := range s.devices(3) {
		if d.ASN != 3 {
			t.Errorf("AS 3's device list includes %s from AS %d", d.ID, d.ASN)
		}
	}
	if len(s.devices(3)) == 0 {
		t.Error("a student sees no devices at all")
	}
	if len(s.devices(999)) != 0 {
		t.Error("an unknown AS produced devices")
	}
}

// The split is decided in two stages, and this covers the first: the shape.
//
// A first word holding a path separator or a shell construct is a command and
// can never be a device name. A bare first word is merely ambiguous, and the
// lookup in the session's own autonomous system decides -- which is the only
// place that answer exists, and the only place the authorisation boundary
// lives.
func TestOnlyABareWordCouldBeADeviceName(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"MSP show ip route", true},
		{"NYC hostname", true},
		// Bare first words: ambiguous by shape, refused by the lookup.
		{"echo hello", true},
		{"cat /etc/passwd", true},
		{"echo a; rm -rf /", true},
		// Unambiguously commands.
		{"/bin/echo hello", false},
		{"./script.sh", false},
		{"a|b c", false},
		{"MSP", false}, // a device with no command is the interactive case
	}
	for _, c := range cases {
		_, _, ok := splitDevicePrefix([]string{"sh", "-c", c.in})
		if ok != c.want {
			t.Errorf("splitDevicePrefix(%q) = %v, want %v", c.in, ok, c.want)
		}
	}
}

// A first word that is not a device is part of the command, not a device that
// does not exist. Getting this wrong tells a student their router is missing
// when they simply ran "echo".
func TestANonDeviceFirstWordStaysPartOfTheCommand(t *testing.T) {
	top := twoASTopology()
	s := &Server{cfg: Config{Topology: top}}
	if _, err := s.resolve(Session{AS: 3}, "echo"); err == nil {
		t.Fatal("the test lab has a device called echo, which invalidates this test")
	}
	name, _, ok := splitDevicePrefix([]string{"sh", "-c", "echo hello"})
	if !ok {
		t.Fatal("the shape was not recognised")
	}
	if _, err := s.resolve(Session{AS: 3}, name); err == nil {
		t.Error("a word that is not a device resolved to one")
	}
}
