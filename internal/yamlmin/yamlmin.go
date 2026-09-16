// Package yamlmin implements a minimal YAML subset parser sufficient for
// dldw configuration files: nested maps, block/inline lists of scalars,
// scalar values (string/int/float/bool/null), '#' comments and blank lines.
// It exists to keep the client zero-dependency. For anything richer, use
// JSON config files, which are fully supported.
package yamlmin

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Unmarshal parses YAML-subset data into v (struct or map) by converting to
// an intermediate map[string]any and reusing encoding/json for mapping.
func Unmarshal(data []byte, v any) error {
	m, err := Parse(data)
	if err != nil {
		return err
	}
	if m == nil {
		return nil
	}
	buf, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return json.Unmarshal(buf, v)
}

type line struct {
	indent int
	text   string
	num    int
}

// Parse converts YAML subset into a map tree.
func Parse(data []byte) (map[string]any, error) {
	var lines []line
	raw := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	for i, l := range raw {
		trimmed := strings.TrimRight(l, " \t")
		stripped := stripComment(trimmed)
		if strings.TrimSpace(stripped) == "" {
			continue
		}
		if strings.TrimSpace(stripped) == "---" {
			continue
		}
		indent := 0
		for indent < len(stripped) && stripped[indent] == ' ' {
			indent++
		}
		if indent < len(stripped) && stripped[indent] == '\t' {
			return nil, fmt.Errorf("yamlmin: tabs not allowed for indentation (line %d)", i+1)
		}
		lines = append(lines, line{indent: indent, text: strings.TrimSpace(stripped), num: i + 1})
	}
	if len(lines) == 0 {
		return nil, nil
	}
	p := &parser{lines: lines}
	m, err := p.parseMap(lines[0].indent)
	if err != nil {
		return nil, err
	}
	if p.pos < len(p.lines) {
		return nil, fmt.Errorf("yamlmin: unexpected content at line %d", p.lines[p.pos].num)
	}
	return m, nil
}

func stripComment(s string) string {
	inS, inD := false, false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			if !inD {
				inS = !inS
			}
		case '"':
			if !inS {
				inD = !inD
			}
		case '#':
			if !inS && !inD && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t') {
				return s[:i]
			}
		}
	}
	return s
}

type parser struct {
	lines []line
	pos   int
}

func (p *parser) parseMap(indent int) (map[string]any, error) {
	out := map[string]any{}
	for p.pos < len(p.lines) {
		ln := p.lines[p.pos]
		if ln.indent < indent {
			return out, nil
		}
		if ln.indent > indent {
			return nil, fmt.Errorf("yamlmin: bad indentation at line %d", ln.num)
		}
		if strings.HasPrefix(ln.text, "- ") || ln.text == "-" {
			return out, nil // list at parent level
		}
		key, rest, err := splitKV(ln.text, ln.num)
		if err != nil {
			return nil, err
		}
		p.pos++
		if rest != "" {
			out[key] = parseScalar(rest)
			continue
		}
		// value is nested block or list
		if p.pos < len(p.lines) && p.lines[p.pos].indent > indent {
			child := p.lines[p.pos]
			if strings.HasPrefix(child.text, "- ") || child.text == "-" {
				lst, lerr := p.parseList(child.indent)
				if lerr != nil {
					return nil, lerr
				}
				out[key] = lst
			} else {
				sub, merr := p.parseMap(child.indent)
				if merr != nil {
					return nil, merr
				}
				out[key] = sub
			}
			continue
		}
		out[key] = nil
	}
	return out, nil
}

func (p *parser) parseList(indent int) ([]any, error) {
	var out []any
	for p.pos < len(p.lines) {
		ln := p.lines[p.pos]
		if ln.indent != indent || !(strings.HasPrefix(ln.text, "- ") || ln.text == "-") {
			return out, nil
		}
		item := strings.TrimSpace(strings.TrimPrefix(ln.text, "-"))
		p.pos++
		if item == "" {
			continue
		}
		out = append(out, parseScalar(item))
	}
	return out, nil
}

func splitKV(s string, num int) (string, string, error) {
	// find first ": " or trailing ":"
	if strings.HasSuffix(s, ":") && !strings.Contains(strings.TrimSuffix(s, ":"), ": ") {
		return unquoteKey(strings.TrimSpace(strings.TrimSuffix(s, ":"))), "", nil
	}
	idx := strings.Index(s, ": ")
	if idx < 0 {
		return "", "", fmt.Errorf("yamlmin: expected 'key: value' at line %d", num)
	}
	key := strings.TrimSpace(s[:idx])
	val := strings.TrimSpace(s[idx+2:])
	return unquoteKey(key), val, nil
}

func unquoteKey(k string) string {
	if len(k) >= 2 && (k[0] == '"' && k[len(k)-1] == '"' || k[0] == '\'' && k[len(k)-1] == '\'') {
		return k[1 : len(k)-1]
	}
	return k
}

func parseScalar(s string) any {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	// inline list [a, b, c]
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		inner := strings.TrimSpace(s[1 : len(s)-1])
		if inner == "" {
			return []any{}
		}
		var out []any
		for _, part := range strings.Split(inner, ",") {
			out = append(out, parseScalar(strings.TrimSpace(part)))
		}
		return out
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		var str string
		if err := json.Unmarshal([]byte(s), &str); err == nil {
			return str
		}
		return s[1 : len(s)-1]
	}
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
	}
	switch strings.ToLower(s) {
	case "true", "yes", "on":
		return true
	case "false", "no", "off":
		return false
	case "null", "~":
		return nil
	}
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return i
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f
	}
	return s
}
