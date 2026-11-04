package collection

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// Export emits the original events, command events, or an Asciicast v2 replay.
// Raw events preserve all bytes. Replay combines adjacent UTF-8 fragments and
// replaces invalid terminal encodings, as required by the JSON string format.
func Export(root, id, format string, out io.Writer) error {
	m, err := ReadMetadata(root, id)
	if err != nil {
		return err
	}
	if format == "activity" || format == "csv" {
		return exportActivities(root, m, format, out)
	}
	enc := json.NewEncoder(out)
	if format == "cast" {
		cols, rows := m.Cols, m.Rows
		if cols < 1 {
			cols = 80
		}
		if rows < 1 {
			rows = 24
		}
		if err := enc.Encode(map[string]any{"version": 2, "width": cols, "height": rows, "timestamp": m.Started.Unix(), "title": m.Lab + " / " + m.Group + " / " + m.ID}); err != nil {
			return err
		}
	} else if format != "events" && format != "commands" {
		return fmt.Errorf("unknown format %q; use events, commands, activity, csv, or cast", format)
	}
	var pending []byte
	var lastTime float64
	flush := func(final bool) error {
		n := len(pending)
		if !final {
			for i := 0; i < len(pending); {
				if !utf8.FullRune(pending[i:]) {
					n = i
					break
				}
				_, size := utf8.DecodeRune(pending[i:])
				i += size
			}
		}
		if n == 0 {
			return nil
		}
		data := strings.ToValidUTF8(string(pending[:n]), "�")
		pending = append([]byte(nil), pending[n:]...)
		return enc.Encode([]any{lastTime, "o", data})
	}
	err = ReadEvents(root, id, func(e Event) error {
		switch format {
		case "events":
			return enc.Encode(e)
		case "commands":
			if strings.HasPrefix(e.Type, "command_") {
				return enc.Encode(e)
			}
			return nil
		}
		lastTime = float64(e.TimeNS) / 1e9
		switch e.Type {
		case "output", "stderr":
			pending = append(pending, e.Data...)
			return flush(false)
		case "input":
			return enc.Encode([]any{lastTime, "i", strings.ToValidUTF8(string(e.Data), "�")})
		case "resize":
			if err := flush(true); err != nil {
				return err
			}
			return enc.Encode([]any{lastTime, "r", fmt.Sprintf("%.0fx%.0f", e.Fields["cols"], e.Fields["rows"])})
		case "device_start":
			return enc.Encode([]any{lastTime, "m", e.Device})
		}
		return nil
	})
	if err == nil && format == "cast" {
		err = flush(true)
	}
	return err
}
