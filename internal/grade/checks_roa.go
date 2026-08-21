package grade

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/svc"
)

func init() {
	Register(&Check{
		Name:     "rpki.roa_published",
		Describe: "the validator holds a ROA authorising this AS to originate its own prefix",
		Run:      checkROAPublished,
	})
}

// checkROAPublished verifies that this AS's prefix is covered by a ROA naming
// this AS as its origin.
//
// Whether this is worth marks depends on the course. In a lab where the
// platform publishes every system's ROA -- which is what the COS-461 example
// does, so that everybody else's routes validate -- it would award the mark to
// everybody for something nobody did, and it is left out of that rubric for
// exactly that reason. It belongs in a rubric where publication is the
// student's own action.
//
// The exercise asks students to publish a ROA for their own address block, and
// nothing checked it. The other RPKI checks are about *reacting* to validation
// state -- refusing invalid routes, keeping not-found ones -- and they can all
// pass on an AS that has published nothing at all, because a network with no
// ROA of its own still sees everybody else's.
//
// It is read from the validator's own table, through the router's session with
// it, so it is the same data the routing policy acts on. A ROA in a file
// somewhere that the validator has not served is not a published ROA.
func checkROAPublished(ctx context.Context, env *Env) Result {
	as, ok := env.Topology.ASes[env.AS]
	if !ok || as.Block == "" {
		return Errored("rpki.roa_published",
			fmt.Errorf("AS %d has no address block in the lab", env.AS))
	}

	// One system is deliberately left without a ROA so that the rest of the
	// internet has a not-found route to keep, which is what makes
	// rpki.notfound_preserved mean anything. Marking its owner down for the
	// lab's own choice would be a mark for something they were never asked to
	// do -- and the lab already declares which system it is, so nobody has to
	// keep the two in step by hand.
	if env.Topology.Lab != nil {
		for _, asn := range env.Topology.Lab.RPKI.NotFound {
			if asn == env.AS {
				return Pass("rpki.roa_published", Evidence{
					Observed: fmt.Sprintf("AS %d is the system this lab deliberately leaves "+
						"without a ROA, so that everybody else has a not-found route to keep",
						env.AS),
					Detail: "declared as rpki.not_found in the manifest",
				})
			}
		}
	}

	// Asked of the trust anchor, not of the student's own router.
	//
	// This read `show rpki prefix-table` from a router of the system being
	// marked. A student has root in their own containers: running a four-line
	// RTR server on one of them and pointing FRR at it produced a prefix table
	// containing whatever they liked, including a ROA for their own prefix
	// that the trust anchor had never issued -- and the question about having
	// published one was answered by the publication being faked. Publication
	// is a fact about the anchor, and the anchor is not theirs.
	published, err := publishedROAs(ctx, env)
	if err != nil {
		return Errored("rpki.roa_published", err)
	}

	want := strings.SplitN(as.Block, "/", 2)
	network := want[0]
	length := ""
	if len(want) == 2 {
		length = want[1]
	}

	var mine, loose, others []string
	for _, v := range published {
		p, l, ok := strings.Cut(v.Prefix, "/")
		if !ok || p != network {
			continue
		}
		if length != "" && l != length {
			continue
		}
		line := fmt.Sprintf("%s maxlen %d origin AS%d", v.Prefix, v.MaxLength, v.ASN)
		if v.ASN == env.AS {
			// A maximum length longer than the prefix authorises every
			// more-specific announcement inside it. That is the attack the
			// exercise is about: with `maxlen 32`, somebody announcing a /16
			// out of this block with this AS forged as the origin is
			// RPKI-valid to everybody who checks, and the ROA that was
			// supposed to stop them is what makes it so. Only the prefix
			// itself is being authorised here.
			if n, err := strconv.Atoi(l); err == nil && v.MaxLength > n {
				loose = append(loose, line)
				continue
			}
			mine = append(mine, line)
			continue
		}
		others = append(others, line)
	}

	if len(mine) == 0 && len(loose) > 0 {
		return Partial("rpki.roa_published", 0.5, Evidence{
			Expected: fmt.Sprintf("a ROA authorising AS %d to originate %s, and nothing "+
				"more specific", env.AS, as.Block),
			Observed: "the ROA authorises every more-specific announcement inside the block",
			Detail:   strings.Join(loose, "\n"),
			Hint: "a maximum length longer than the prefix makes a hijack of a smaller " +
				"piece of your address space valid to everybody who checks; set it to the " +
				"length of the block",
			Command: "GET /roas on the publication service",
		})
	}
	if len(mine) > 0 {
		return Pass("rpki.roa_published", Evidence{
			Observed: fmt.Sprintf("the trust anchor holds a ROA authorising AS %d to originate %s",
				env.AS, as.Block),
			Detail:  strings.Join(mine, "\n"),
			Command: "GET /roas on the publication service",
		})
	}
	if len(others) > 0 {
		return Fail("rpki.roa_published", Evidence{
			Expected: fmt.Sprintf("a ROA for %s with origin AS %d", as.Block, env.AS),
			Observed: "the validator holds a ROA for this prefix, but authorising a different AS",
			Detail:   strings.Join(others, "\n"),
			Hint: "the origin AS in the ROA has to be the one that announces the prefix, " +
				"or your own announcement is invalid to everybody who checks",
			Command: "show rpki prefix-table",
		})
	}
	return Fail("rpki.roa_published", Evidence{
		Expected: fmt.Sprintf("a ROA for %s with origin AS %d", as.Block, env.AS),
		Observed: "the validator holds no ROA for this prefix at all",
		Hint: "publish a ROA for your own block; without one your announcement is " +
			"not-found to everybody, and a network that rejects not-found cannot reach you",
		Command: "show rpki prefix-table",
	})
}

// publishedVRP is one authorisation the trust anchor holds.
type publishedVRP struct {
	Prefix    string `json:"prefix"`
	MaxLength int    `json:"maxLength"`
	ASN       int    `json:"asn"`
}

// publishedROAs asks the lab's trust anchor what it has published.
//
// The request is made from inside the anchor's own container, so it cannot be
// intercepted by anything a student controls: they have root in their routers
// and hosts, and can point their validator session wherever they like, but the
// publication service is the platform's.
func publishedROAs(ctx context.Context, env *Env) ([]publishedVRP, error) {
	dev := rpkiServiceDevice(env)
	if dev == "" {
		return nil, fmt.Errorf("this lab has no RPKI publication service, so whether a ROA " +
			"was published cannot be established")
	}
	res, err := env.Probe(ctx, dev, []string{"sh", "-c",
		fmt.Sprintf("wget -qO- http://127.0.0.1%s/roas", svc.PublishListen)})
	if err != nil {
		return nil, fmt.Errorf("asking %s what it has published: %w", dev, err)
	}
	body := strings.TrimSpace(res.Stdout)
	if body == "" {
		return nil, fmt.Errorf("%s returned nothing when asked what it has published", dev)
	}
	var out []publishedVRP
	if jerr := json.Unmarshal([]byte(body), &out); jerr != nil {
		return nil, fmt.Errorf("reading what %s has published: %w", dev, jerr)
	}
	return out, nil
}

// rpkiServiceDevice finds the trust anchor in the lab.
func rpkiServiceDevice(env *Env) string {
	for _, name := range env.Topology.SortedServiceNames() {
		service := env.Topology.Services[name]
		if service == nil || !strings.Contains(strings.ToLower(service.Kind), "rpki") {
			continue
		}
		if replica, ok := service.ReplicaForAS(env.AS); ok && replica != nil && replica.Device != nil {
			return replica.Device.ID
		}
		if service.Device != nil {
			return service.Device.ID
		}
	}
	for _, d := range env.Topology.SortedDevices() {
		if d.Kind == model.KindService && strings.Contains(strings.ToLower(d.ID), "rpki") {
			return d.ID
		}
	}
	return ""
}
