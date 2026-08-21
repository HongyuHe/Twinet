package cli

import "testing"

func TestParseImagePinsRejectsMutableAndPreservesDigest(t *testing.T) {
	const digest = "registry.example/router@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	pins, err := parseImagePins([]string{"registry.example/router:v1=" + digest})
	if err != nil {
		t.Fatal(err)
	}
	if pins["registry.example/router:v1"] != digest {
		t.Fatalf("pin map = %#v", pins)
	}
	if _, err := parseImagePins([]string{"registry.example/router:v1=sha256:aaaaaaaa"}); err == nil {
		t.Fatal("mutable/local image ID pin was accepted")
	}
}
