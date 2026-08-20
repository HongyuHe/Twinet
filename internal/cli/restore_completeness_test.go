package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

// restoreTopology builds a one-AS lab with a router and a trust anchor cabled
// to it, which is what replaying published authorisations needs.
func restoreTopology() *model.Topology {
	router := &model.Device{ID: "as3/ATL", Name: "ATL", Kind: model.KindRouter, ASN: 3}
	rpki := &model.Device{
		ID: "svc/rpki", Name: "rpki", Kind: model.KindService, ServiceKind: "builtin.rpki",
		Ifaces: []*model.Iface{{Name: "as3", Addr4: "10.9.0.1/24"}},
	}
	as := &model.AS{
		ASN: 3, Role: model.RoleStudent, OwnerGroup: "group3",
		Devices: []*model.Device{router}, Routers: []*model.Device{router},
	}
	return &model.Topology{
		Name: "cos461", Hash: "abc123",
		ASes:    map[int]*model.AS{3: as},
		Devices: map[string]*model.Device{router.ID: router, rpki.ID: rpki},
	}
}

func bundleFor(files map[string][]byte) (Bundle, map[string][]byte) {
	b := Bundle{Lab: "cos461", AS: 3, Group: "group3", Files: map[string]string{}}
	for n := range files {
		b.Files[n] = ""
	}
	return b, files
}

// Publishing a ROA is a student action and lives in no router's running-config,
// so the archive is the only record of it. restoreBundle matched archive
// members by file extension and processed only .conf and .sh, so roas.json --
// which the save side adds precisely so the answer survives a rebuild -- was
// stepped over in silence and the restore reported success. Graded afterwards
// in a lab whose trust anchor starts empty, the group loses the mark for
// publishing, having done it correctly.
func TestRestorePutsBackPublishedAuthorisations(t *testing.T) {
	top := restoreTopology()
	b, files := bundleFor(map[string][]byte{
		"ATL.conf":  []byte("router bgp 3\n"),
		"roas.json": []byte(`[{"prefix":"3.0.0.0/8","maxLength":8,"asn":3}]`),
	})

	var published []string
	exec := func(_ context.Context, id string, cmd []string) (execResult, error) {
		if len(cmd) > 1 && strings.Contains(cmd[len(cmd)-1], "/roas") {
			published = append(published, id+": "+cmd[len(cmd)-1])
			return execResult{}, nil
		}
		return execResult{}, nil
	}

	if _, err := restoreBundle(context.Background(), top, b, files, exec); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if len(published) != 1 {
		t.Fatalf("the archive's ROA was never published: %d publish attempt(s)", len(published))
	}
	if !strings.Contains(published[0], "3.0.0.0/8") {
		t.Errorf("published something other than the archive's ROA: %s", published[0])
	}
}

// The archive is one Twinet wrote and signed, so a member this code does not
// recognise is not junk to skip: it is part of the saved answer that this
// version cannot put back. Reporting the restore as complete would tell an
// operator the work is loaded when some of it is not -- which is exactly how
// roas.json came to be lost. Any future addition to the save side must be
// refused loudly by an older restore rather than dropped.
func TestRestoreRefusesAnArchiveMemberItCannotApply(t *testing.T) {
	top := restoreTopology()
	b, files := bundleFor(map[string][]byte{
		"ATL.conf":     []byte("router bgp 3\n"),
		"answers.yaml": []byte("q1: yes\n"),
	})

	exec := func(context.Context, string, []string) (execResult, error) {
		return execResult{}, nil
	}

	_, err := restoreBundle(context.Background(), top, b, files, exec)
	if err == nil {
		t.Fatal("restore accepted an archive member it never applied and reported success")
	}
	if !strings.Contains(err.Error(), "answers.yaml") {
		t.Errorf("the refusal does not name the member that was not applied: %v", err)
	}
}

// The control: the refusal must not fire on an archive this version fully
// understands, which is every archive in use today.
func TestRestoreAcceptsAnArchiveItFullyApplies(t *testing.T) {
	top := restoreTopology()
	b, files := bundleFor(map[string][]byte{
		"ATL.conf": []byte("router bgp 3\n"),
		"ATL.sh":   []byte("ip addr replace 3.0.0.1/24 dev port_a\n"),
	})

	exec := func(context.Context, string, []string) (execResult, error) {
		return execResult{}, nil
	}

	n, err := restoreBundle(context.Background(), top, b, files, exec)
	if err != nil {
		t.Fatalf("restore refused an archive it fully understands: %v", err)
	}
	if n != 2 {
		t.Errorf("restored %d device entries, want 2", n)
	}
}

// Restore and batch grading each decided separately what an archive may
// contain, which is how one of them came to ignore the published
// authorisations while the other applied them. Both now ask the same
// classifier, so a member added to the save side cannot be handled in one
// consumer and forgotten in the other; whichever has not been taught about it
// refuses by name instead of marking a group on part of their work.
func TestBundleClassifierPlacesEveryMemberOrRefuses(t *testing.T) {
	m, err := classifyBundle(map[string][]byte{
		"ATL.conf":  []byte("router bgp 3\n"),
		"h1.sh":     []byte("ip route replace default via 3.0.0.2\n"),
		"roas.json": []byte("[]"),
	})
	if err != nil {
		t.Fatalf("refused an archive of the shape every save produces: %v", err)
	}
	if len(m.Configs) != 1 || len(m.Scripts) != 1 || len(m.ROAs) == 0 {
		t.Errorf("misplaced a member: %d config(s), %d script(s), %d ROA byte(s)",
			len(m.Configs), len(m.Scripts), len(m.ROAs))
	}

	if _, err := classifyBundle(map[string][]byte{
		"ATL.conf":    []byte("router bgp 3\n"),
		"answers.txt": []byte("q1: yes\n"),
	}); err == nil {
		t.Error("placed nothing for a member it does not understand, and said so to nobody")
	}
}
