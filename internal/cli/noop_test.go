package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestNoopFallbackDiagnosticsAreVerboseAndJSONSafe(t *testing.T) {
	reasons := map[string]string{
		"node-b": "local no-op witness changed before verification",
		"node-a": "committed generation differs from cluster generation",
	}
	t.Run("verbose", func(t *testing.T) {
		var out bytes.Buffer
		if err := writeNoopFallback(&out, reasons, true, false); err != nil {
			t.Fatal(err)
		}
		text := out.String()
		if !strings.Contains(text, "no-op preflight fallback:") ||
			!strings.Contains(text, "node-a: committed generation") ||
			!strings.Contains(text, "node-b: local no-op witness") {
			t.Fatalf("verbose fallback = %q", text)
		}
		if strings.Index(text, "node-a") > strings.Index(text, "node-b") {
			t.Fatalf("verbose fallback was not deterministic: %q", text)
		}
	})
	t.Run("json", func(t *testing.T) {
		var out bytes.Buffer
		if err := writeNoopFallback(&out, reasons, false, true); err != nil {
			t.Fatal(err)
		}
		var got noopFallback
		if err := json.Unmarshal(out.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.Noop || got.Reasons["node-a"] == "" || got.Reasons["node-b"] == "" {
			t.Fatalf("JSON fallback = %#v", got)
		}
	})
}
