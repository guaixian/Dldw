package cli

import (
	"fmt"
	"os"
	"strings"
)

// flagSet is a tiny flag parser supporting --name value / --name=x /
// -name value forms plus bool flags and interspersed positionals.
type flagSet struct {
	name  string
	strs  map[string]*string
	bools map[string]*bool
	ints  map[string]*int
}

func newFlagSet(name string) *flagSet {
	return &flagSet{name: name, strs: map[string]*string{}, bools: map[string]*bool{}, ints: map[string]*int{}}
}

func (f *flagSet) StrVar(p *string, name, def string) {
	*p = def
	f.strs[name] = p
}

func (f *flagSet) BoolVar(p *bool, name string, def bool) {
	*p = def
	f.bools[name] = p
}

func (f *flagSet) IntVar(p *int, name string, def int) {
	*p = def
	f.ints[name] = p
}

// StrVarHelp registers a string flag with a usage hint (hint unused for now).
func (f *flagSet) StrVarHelp(p *string, name, def, hint string) { f.StrVar(p, name, def) }

// BoolVarHelp registers a bool flag with a usage hint.
func (f *flagSet) BoolVarHelp(p *bool, name string, def bool, hint string) { f.BoolVar(p, name, def) }

// IntVarHelp registers an int flag with a usage hint.
func (f *flagSet) IntVarHelp(p *int, name string, def int, hint string) { f.IntVar(p, name, def) }

// Parse consumes args; returns positional arguments.
func (f *flagSet) Parse(args []string) (first string, rest []string) {
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") || a == "-" {
			pos = append(pos, a)
			continue
		}
		name := strings.TrimLeft(a, "-")
		val := ""
		hasVal := false
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			val, name, hasVal = name[eq+1:], name[:eq], true
		}
		if p, ok := f.bools[name]; ok {
			if hasVal {
				*p = val == "true" || val == "1" || val == "yes"
			} else {
				*p = true
			}
			continue
		}
		if p, ok := f.strs[name]; ok {
			if !hasVal {
				if i+1 >= len(args) {
					f.fail("flag --%s requires a value", name)
				}
				i++
				val = args[i]
			}
			*p = val
			continue
		}
		if p, ok := f.ints[name]; ok {
			if !hasVal {
				if i+1 >= len(args) {
					f.fail("flag --%s requires a value", name)
				}
				i++
				val = args[i]
			}
			n := 0
			if _, err := fmt.Sscanf(val, "%d", &n); err != nil {
				f.fail("flag --%s: bad integer %q", name, val)
			}
			*p = n
			continue
		}
		f.fail("unknown flag --%s for %s", name, f.name)
	}
	if len(pos) > 0 {
		return pos[0], pos[1:]
	}
	return "", nil
}

func (f *flagSet) fail(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "dldw %s: %s\n", f.name, msg)
	os.Exit(2)
}
