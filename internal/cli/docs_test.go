package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Documentation that names a command which does not exist is worse than
// documentation that omits it. The reader types what they were told to type,
// gets "unknown command", and has no way to tell whether they made a mistake,
// whether the tool is broken, or whether the manual is describing something
// that was never built. For a project whose whole justification is being easier
// to use than the pile of shell scripts it replaces, that is not a cosmetic
// problem.
//
// Nine such commands accumulated -- twinet gen, twinet attach, twinet events,
// twinet import, twinet behaviour, twinet images push, twinet grade --live,
// twinet grade replay, twinet inspect placement -- across five documents, all
// written in the present tense as though they worked.
//
// Prose is not checked by a compiler, so this stands in for one. Any command
// named in the documentation must either exist, or sit on a line that says
// plainly it does not yet.
func TestEveryDocumentedCommandExists(t *testing.T) {
	root := Root()

	docs, err := filepath.Glob("../../docs/*.md")
	if err != nil {
		t.Fatal(err)
	}
	docs = append(docs, "../../README.md")

	// "twinet foo bar" -- the longest run of lowercase words after the binary
	// name. Flags, paths and placeholders end the run.
	ref := regexp.MustCompile(`twinet((?: [a-z][a-z0-9-]*)+)`)

	var problems []string
	for _, path := range docs {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		inFence := false
		for i, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "```") {
				inFence = !inFence
			}
			if plannedContext(path, line) {
				continue
			}
			for _, m := range ref.FindAllStringSubmatch(line, -1) {
				words := strings.Fields(m[1])
				if len(words) == 0 {
					continue
				}
				if cmd, missing := resolve(root, words); missing != "" {
					problems = append(problems, formatProblem(path, i+1, line, cmd, missing))
				}
			}
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		t.Errorf("the documentation names %d command(s) that do not exist:\n\n%s\n\n"+
			"Either build them, correct the name, or say on the same line that they are "+
			"planned (\"roadmap\", \"not yet\", \"planned\", \"will\", \"would\").",
			len(problems), strings.Join(problems, "\n"))
	}
}

// A documented flag that does not exist fails in exactly the same way as a
// documented command that does not exist: the reader types the line, gets
// "unknown flag", and cannot tell whether the tool or the manual is wrong.
// Command names were checked and flags were not, so the guidance that told an
// operator which flag to pass was unchecked prose next to checked prose.
//
// Every flag written after a command in the documentation must exist on that
// command, or be inherited by it.
func TestEveryDocumentedFlagExists(t *testing.T) {
	root := Root()

	docs, err := filepath.Glob("../../docs/*.md")
	if err != nil {
		t.Fatal(err)
	}
	docs = append(docs, "../../README.md")

	// The command, then everything up to the end of the line or the start of
	// another command: a pipe, a chained command, a redirection, or a comment.
	invocation := regexp.MustCompile(`twinet((?: [a-z][a-z0-9-]*)+)([^|&;>#\n]*)`)
	flagRef := regexp.MustCompile(`(^|\s)--([a-z][a-z0-9-]*)`)

	var problems []string
	for _, path := range docs {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(raw), "\n") {
			if plannedContext(path, line) {
				continue
			}
			for _, m := range invocation.FindAllStringSubmatch(line, -1) {
				words := strings.Fields(m[1])
				if len(words) == 0 {
					continue
				}
				cmd, missing := resolve(root, words)
				if missing != "" {
					// The command itself is wrong, which the other gate
					// reports. Its flags cannot be judged.
					continue
				}
				for _, f := range flagRef.FindAllStringSubmatch(m[2], -1) {
					name := f[2]
					if cmd.Flags().Lookup(name) != nil ||
						cmd.InheritedFlags().Lookup(name) != nil ||
						root.PersistentFlags().Lookup(name) != nil {
						continue
					}
					problems = append(problems, "  "+filepath.Base(path)+":"+
						strconv.Itoa(i+1)+": "+cmd.CommandPath()+" has no --"+name+
						"\n      "+strings.TrimSpace(line)+
						"\n      it accepts: "+strings.Join(flagNames(cmd), ", "))
				}
			}
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		t.Errorf("the documentation names %d flag(s) that do not exist:\n\n%s\n\n"+
			"Either add them, correct the name, or say on the same line that they are planned.",
			len(problems), strings.Join(problems, "\n"))
	}
}

// flagNames lists what a command does accept, so a failure names the
// alternative instead of only the mistake.
func flagNames(cmd *cobra.Command) []string {
	seen := map[string]bool{}
	var out []string
	add := func(f *pflag.Flag) {
		if f.Hidden || seen[f.Name] {
			return
		}
		seen[f.Name] = true
		out = append(out, "--"+f.Name)
	}
	cmd.Flags().VisitAll(add)
	cmd.InheritedFlags().VisitAll(add)
	sort.Strings(out)
	return out
}

// resolve walks as far down the command tree as the words allow. It returns the
// deepest command matched and, if the *first* unmatched word looks like a
// subcommand rather than an argument, that word.
//
// Only the first word after a valid command is checked. "twinet exec as3/ZURI"
// names a device, not a subcommand, and the manual is full of such lines; but
// "twinet gen internet" names nothing at all, and neither does "twinet gen".
func resolve(root *cobra.Command, words []string) (*cobra.Command, string) {
	cur := root
	for i, w := range words {
		next := child(cur, w)
		if next != nil {
			cur = next
			continue
		}
		// An unknown word directly after the binary name is always wrong:
		// there is no command for it to be an argument of.
		if i == 0 {
			return root, w
		}
		// Deeper down, an unknown word is an argument if the command takes
		// any, and a bad subcommand if it only has children.
		if len(cur.Commands()) > 0 && !cur.Runnable() {
			return cur, w
		}
		return cur, ""
	}
	// A command group with no runnable body, named on its own, is still a real
	// thing to write about ("twinet fault" as a heading), so it is allowed.
	return cur, ""
}

func child(c *cobra.Command, name string) *cobra.Command {
	for _, sub := range c.Commands() {
		if sub.Name() == name {
			return sub
		}
		for _, a := range sub.Aliases {
			if a == name {
				return sub
			}
		}
	}
	return nil
}

// plannedContext reports whether a line admits that what it describes does not
// exist yet. The roadmap is entirely future work, so it is exempt wholesale.
func plannedContext(path, line string) bool {
	if strings.Contains(path, "roadmap") {
		return true
	}
	low := strings.ToLower(line)
	for _, marker := range []string{
		"roadmap", "not yet", "planned", "will be", "would be", "to be built",
		"does not exist", "unimplemented", "future", "m7", "m8", "m9",
	} {
		if strings.Contains(low, marker) {
			return true
		}
	}
	return false
}

func formatProblem(path string, line int, text string, cmd *cobra.Command, missing string) string {
	var have []string
	for _, sub := range cmd.Commands() {
		if !sub.Hidden {
			have = append(have, sub.Name())
		}
	}
	sort.Strings(have)
	full := "twinet " + missing
	if cmd.Name() != "twinet" {
		full = cmd.CommandPath() + " " + missing
	}
	return "  " + filepath.Base(path) + ":" + strconv.Itoa(line) + ": " + full +
		"\n      " + strings.TrimSpace(text) +
		"\n      " + cmd.CommandPath() + " has: " + strings.Join(have, ", ")
}
